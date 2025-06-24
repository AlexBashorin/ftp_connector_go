package main

import (
	"crypto/tls"
	"ftp_connector/config"
	handletlsresumption "ftp_connector/internal/handle_tls_resumption"
	"log"
	"net/http"
	"strings"
)

// Глобальный TLS session cache для переиспользования сессий
var globalTLSSessionCache = tls.NewLRUClientSessionCache(64)

// Через переменные окружения передаем нужные адреса
var allowedOrigins map[string]bool

// Пути к сертификатам
var certPath = "./certs/mycert.pfx"

func main() {
	// Проверка обязательных переменных окружения
	envs, err := config.MustLoad()
	if err != nil {
		log.Fatal(err)
	}

	pfxPass := envs.FTPS_PFX_PASSWORD

	allowedOrigins = make(map[string]bool)
	for _, origin := range strings.Split(envs.ALLOWED_ORIGINS, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allowedOrigins[origin] = true
		}
	}

	ftpsHandler := handletlsresumption.NewFTPSDownloadHandler(globalTLSSessionCache, pfxPass)

	// Настройка HTTP сервера
	http.HandleFunc("/ftp/download", corsMiddleware(ftpsHandler))

	log.Println("Starting FTPS service on port 2992 with TLS session resumption enabled")
	if err := http.ListenAndServe(":2992", nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// corsMiddleware добавляет CORS заголовки
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}
