package handletlsresumption

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"ftp_connector/models"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
	"golang.org/x/crypto/pkcs12"
)

// Глобальный TLS session cache для переиспользования сессий
// var globalTLSSessionCache = tls.NewLRUClientSessionCache(64)

// Пути к сертификатам
var certPath = "./certs/mycert.pfx"

// NewFTPSDownloadHandler фабрика подключения к FTP и скачивание файла
func NewFTPSDownloadHandler(
	sessionCache tls.ClientSessionCache,
	pfxPass string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Функция для отправки JSON ошибки
		sendError := func(status int, message string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(models.ErrorResponse{
				Success: false,
				Error:   message,
			})
		}

		if r.Method != http.MethodPost {
			sendError(http.StatusMethodNotAllowed, "Only POST method is allowed")
			return
		}

		var req models.FTPSRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendError(http.StatusBadRequest, "Invalid JSON format: "+err.Error())
			return
		}

		// Валидация входных данных
		if err := validateRequest(&req); err != nil {
			sendError(http.StatusBadRequest, err.Error())
			return
		}

		// Скачивание файла
		data, err := downloadFTPSFile(req.Host, req.Port, req.Username, req.Password,
			req.RemotePath, certPath, pfxPass, sessionCache)
		if err != nil {
			log.Printf("FTPS download error: %v", err)
			sendError(http.StatusInternalServerError, "Failed to download file: "+err.Error())
			return
		}

		// Проверяем, что данные не пустые
		if len(data) == 0 {
			sendError(http.StatusInternalServerError, "Downloaded file is empty")
			return
		}

		// Отправляем JSON с информацией о файле и самим файлом
		w.Header().Set("Content-Type", "application/json")
		response := models.FTPSResponse{
			Success: true,
			Message: fmt.Sprintf("File downloaded successfully, size: %d bytes", len(data)),
			Size:    len(data),
			Data:    base64.StdEncoding.EncodeToString(data),
		}
		json.NewEncoder(w).Encode(response)
	}
}

// HandleFTPSDownload обрабатывает POST запросы для скачивания файлов через FTPS
// func HandleFTPSDownload(w http.ResponseWriter, r *http.Request) {
// }

// validateRequest валидирует входящий запрос
func validateRequest(req *models.FTPSRequest) error {
	if req.Host == "" {
		return errors.New("host is required")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return errors.New("invalid port number")
	}
	if req.Username == "" {
		return errors.New("username is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	if req.RemotePath == "" {
		return errors.New("remote path is required")
	}
	return nil
}

// downloadFTPSFile скачивает файл через implicit FTPS с поддержкой TLS session resumption
func downloadFTPSFile(host string, port int, username, password, remotePath,
	certPath, pfxPassword string, sessionCache tls.ClientSessionCache) ([]byte, error) {

	// Загрузка и парсинг сертификата
	cert, err := loadTLSCertificate(certPath, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("loading TLS certificate: %w", err)
	}

	// Настройка TLS конфигурации для implicit FTPS с включенным session resumption
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         host,

		// ВКЛЮЧАЕМ TLS SESSION RESUMPTION:
		SessionTicketsDisabled: false,        // Включаем session tickets
		ClientSessionCache:     sessionCache, // Используем глобальный cache

		// Дополнительные настройки для стабильности:
		PreferServerCipherSuites: true,                        // Позволяем серверу выбирать cipher suites
		Renegotiation:            tls.RenegotiateOnceAsClient, // Разрешаем одно renegotiation

		// Настройки для лучшей совместимости:
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},

		// Callback для отслеживания handshake
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			log.Printf("Server requested client certificate")
			return &cert, nil
		},
	}

	// Подключение к FTPS серверу (implicit mode)
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("Connecting to FTPS server at %s with TLS session resumption enabled", addr)

	// Создаем соединение с расширенными настройками
	client, err := ftp.Dial(addr,
		ftp.DialWithTimeout(60*time.Second),
		ftp.DialWithTLS(tlsConfig),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to FTPS server %s: %w", addr, err)
	}
	defer func() {
		if err := client.Quit(); err != nil {
			log.Printf("Error closing FTPS connection: %v", err)
		}
	}()

	// Аутентификация
	log.Printf("Attempting to login with username: %s", username)
	if err := client.Login(username, password); err != nil {
		return nil, fmt.Errorf("FTPS authentication failed for user %s: %w", username, err)
	}
	log.Printf("Successfully logged in")

	// Принудительно устанавливаем бинарный режим передачи данных
	if err := client.Type(ftp.TransferTypeBinary); err != nil {
		log.Printf("Warning: failed to set binary mode: %v", err)
	}

	// Обработка пути - убираем начальный слеш если есть
	fileName := strings.TrimPrefix(remotePath, "/")
	log.Printf("Attempting to retrieve file: %s", fileName)

	// Скачивание файла с дополнительным логированием
	log.Printf("Initiating file transfer with TLS session resumption")
	resp, err := client.Retr(fileName)
	if err != nil {
		return nil, fmt.Errorf("retrieving file %s: %w", fileName, err)
	}

	// Читаем все данные сразу с помощью io. ReadAll
	log.Printf("Starting file transfer")
	data, err := io.ReadAll(resp)
	if err != nil {
		resp.Close() // Закрываем соединение при ошибке
		return nil, fmt.Errorf("reading file data: %w", err)
	}

	log.Printf("File data read successfully, size: %d bytes", len(data))

	// Закрываем соединение для передачи данных
	if err := resp.Close(); err != nil {
		// С session resumption может быть меньше ошибок 425
		log.Printf("Data connection close returned: %v", err)

		// Если это ошибка 425, но данные получены - не считаем критичной
		if strings.Contains(err.Error(), "425") && len(data) > 0 {
			log.Printf("Received 425 error but data was successfully transferred")
		} else if len(data) == 0 {
			return nil, fmt.Errorf("connection closed with error and no data received: %w", err)
		}
	}

	// Проверяем, что мы получили данные
	if len(data) == 0 {
		return nil, fmt.Errorf("no data received from server")
	}

	log.Printf("File transfer completed successfully with TLS session resumption, total size: %d bytes", len(data))
	return data, nil
}

// loadTLSCertificate загружает и расшифровывает TLS сертификат из PFX файла
func loadTLSCertificate(certPath, pfxPassword string) (tls.Certificate, error) {
	// Проверяем пароль
	if pfxPassword == "" {
		return tls.Certificate{}, errors.New("PFX password is required")
	}

	// Читаем PFX файл
	pfxData, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading PFX file %s: %w", certPath, err)
	}

	var errorDetails strings.Builder

	// Разбираем PFX файл
	privateKey, cert, err := pkcs12.Decode(pfxData, pfxPassword)
	if err != nil {
		errorDetails.WriteString(fmt.Sprintf("Failed to decode PFX: %v\n", err))
		return tls.Certificate{}, fmt.Errorf("failed to decode PFX file. Details:\n%s", errorDetails.String())
	}

	// Проверяем, что это RSA ключ
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		errorDetails.WriteString("Private key is not RSA\n")
		return tls.Certificate{}, fmt.Errorf("private key is not RSA. Details:\n%s", errorDetails.String())
	}

	// Создаем сертификат
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  rsaKey,
		Leaf:        cert,
	}, nil
}
