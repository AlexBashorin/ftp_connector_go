package config

import (
	"errors"
	"os"
)

type Environment struct {
	FTPS_KEY_PASSWORD string `json:"FTPS_KEY_PASSWORD"`
	FTPS_CERT_PATH    string `json:"FTPS_CERT_PATH"`
}

func MustLoad() (Environment, error) {
	var envr Environment

	envr.FTPS_KEY_PASSWORD = os.Getenv("FTPS_KEY_PASSWORD")
	if envr.FTPS_KEY_PASSWORD == "" {
		return envr, errors.New("FTPS_KEY_PASSWORD environment variable is not set")
	}

	envr.FTPS_CERT_PATH = os.Getenv("FTPS_CERT_PATH")
	if envr.FTPS_CERT_PATH == "" {
		return envr, errors.New("FTPS_CERT_PATH environment variable is not set")
	}
	return envr, nil
}
