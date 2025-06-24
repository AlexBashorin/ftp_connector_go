package models

// FTPSRequest представляет структуру запроса
type FTPSRequest struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	RemotePath string `json:"remote_path"`
}

// FTPSResponse представляет структуру ответа
type FTPSResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Size    int    `json:"size,omitempty"`
	Data    string `json:"data,omitempty"` // base64
}

// ErrorResponse представляет структуру ошибки
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}
