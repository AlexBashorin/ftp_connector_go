package config

import (
	"errors"
	"os"
)

type Environment struct {
	FTPS_PFX_PASSWORD string `json:"FTPS_PFX_PASSWORD"`
	ALLOWED_ORIGINS   string `json:"ALLOWED_ORIGINS"`
}

func MustLoad() (Environment, error) {
	var envr Environment

	envr.FTPS_PFX_PASSWORD = os.Getenv("FTPS_PFX_PASSWORD")
	if envr.FTPS_PFX_PASSWORD == "" {
		return envr, errors.New("FTPS_PFX_PASSWORD environment variable is not set")
	}

	envr.ALLOWED_ORIGINS = os.Getenv("ALLOWED_ORIGINS")
	if envr.ALLOWED_ORIGINS == "" {
		return envr, errors.New("ALLOWED_ORIGINS environment variable is not set")
	}

	return envr, nil
}
