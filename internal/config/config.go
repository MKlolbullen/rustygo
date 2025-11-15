package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type ToolPaths struct {
	Subfinder   string `json:"subfinder"`
	Assetfinder string `json:"assetfinder"`
}

type APIKeys struct {
	Shodan       string `json:"shodan"`
	CensysID     string `json:"censys_id"`
	CensysSecret string `json:"censys_secret"`
	// add more as needed
}

type Config struct {
	ToolPaths ToolPaths `json:"tool_paths"`
	APIKeys   APIKeys   `json:"api_keys"`
}

func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// NOTE: app dir = rustygo
	return filepath.Join(home, ".config", "rustygo", "config.json"), nil
}

func Load() (*Config, error) {
	path, err := DefaultConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}
