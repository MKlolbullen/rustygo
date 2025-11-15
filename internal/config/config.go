package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ToolPaths holds absolute paths to external binaries. If empty, PATH will be used.
type ToolPaths struct {
	// Existing recon tools
	Subfinder   string `json:"subfinder"`
	Assetfinder string `json:"assetfinder"`
	Dnsx        string `json:"dnsx"`
	Httpx       string `json:"httpx"`
	Naabu       string `json:"naabu"`
	Nuclei      string `json:"nuclei"`

	// Windows / AD / network tools
	Enum4linux string `json:"enum4linux_ng"` // enum4linux-ng
	Nbtstat    string `json:"nbtstat"`       // nbtstat or nbtscan
	Netexec    string `json:"netexec"`       // netexec (crackmapexec successor)
	Smbclient  string `json:"smbclient"`
	Smbmap     string `json:"smbmap"`

	// LDAP / directory
	Ldapsearch string `json:"ldapsearch"`

	// C2 tooling
	HavocClient string `json:"havoc_client"`

	// Metasploit
	Msfconsole string `json:"msfconsole"`
}

// APIKeys holds API credentials and URLs for various services.
type APIKeys struct {
	Shodan       string `json:"shodan"`
	CensysID     string `json:"censys_id"`
	CensysSecret string `json:"censys_secret"`

	// Empire API configuration for interacting with PowerShell Empire via its REST interface.
	EmpireAPIURL   string `json:"empire_api_url"`
	EmpireUser     string `json:"empire_user"`
	EmpirePass     string `json:"empire_pass"`
	EmpireAPIToken string `json:"empire_api_token"`

	// Adaptix API configuration for interacting with Adaptix C2.
	AdaptixAPIURL  string `json:"adaptix_api_url"`
	AdaptixUsername string `json:"adaptix_username"`
	AdaptixPassword string `json:"adaptix_password"`
}

// Config is the top-level configuration for rustygo.
type Config struct {
	ToolPaths ToolPaths `json:"tool_paths"`
	APIKeys   APIKeys   `json:"api_keys"`
}

// DefaultConfigPath returns the default config file location.
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "rustygo", "config.json"), nil
}

// Load reads configuration from disk.
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
