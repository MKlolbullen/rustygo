package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ToolPaths contains paths to external binaries used by rustygo.
type ToolPaths struct {
	// Recon / discovery
	Subfinder   string `json:"subfinder"`
	Assetfinder string `json:"assetfinder"`
	Dnsx        string `json:"dnsx"`
	Httpx       string `json:"httpx"`
	Naabu       string `json:"naabu"`
	Nuclei      string `json:"nuclei"`

	// Web discovery / recon
	Ffuf        string `json:"ffuf"`
	Feroxbuster string `json:"feroxbuster"`
	Whatweb     string `json:"whatweb"`
	Favirecon   string `json:"favirecon"`
	Csprecon    string `json:"csprecon"`
	Nextnet     string `json:"nextnet"`

	// Screenshot tool (e.g. gowitness)
	ScreenshotTool string `json:"screenshot_tool"`

	// Windows / internal enum tools
	Enum4linuxNG string `json:"enum4linux_ng"`
	Nbtstat      string `json:"nbtstat"`      // or nbtscan, etc.
	Netexec      string `json:"netexec_path"` // path to netexec / nxc

	// C2 clients
	HavocClient string `json:"havoc_client"`
}

// APIKeys contains API credentials for external services.
type APIKeys struct {
	// OSINT / enrichment
	Shodan       string `json:"shodan"`
	CensysID     string `json:"censys_id"`
	CensysSecret string `json:"censys_secret"`

	BinaryEdge  string `json:"binaryedge"`
	IPInfoToken string `json:"ipinfo_token"`
	URLScanKey  string `json:"urlscan_key"`
	VirusTotal  string `json:"virustotal"`
	NetlasToken string `json:"netlas_token"`
	DNSTwister  string `json:"dnstwister"`

	// Empire API configuration
	EmpireAPIURL   string `json:"empire_api_url"`
	EmpireUser     string `json:"empire_user"`
	EmpirePass     string `json:"empire_pass"`
	EmpireAPIToken string `json:"empire_api_token"`

	// Adaptix API configuration
	AdaptixAPIURL  string `json:"adaptix_api_url"`
	AdaptixUsername string `json:"adaptix_username"`
	AdaptixPassword string `json:"adaptix_password"`
}

// ScriptConfig describes a script that can be run via CLI/GUI.
type ScriptConfig struct {
	Name        string   `json:"name"`                  // id used from CLI/UI
	Path        string   `json:"path"`                  // path to the script file
	Interpreter string   `json:"interpreter,omitempty"` // default: "ruby"
	Args        []string `json:"args,omitempty"`        // default args before user args
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// Config is the top-level configuration for rustygo.
type Config struct {
	ToolPaths ToolPaths      `json:"tool_paths"`
	APIKeys   APIKeys        `json:"api_keys"`
	Scripts   []ScriptConfig `json:"scripts,omitempty"`
}

// DefaultConfigPath returns the default path to config.json.
func DefaultConfigPath() (string, error) {
	// Simple default: ./config.json, or override via RUSTYGO_CONFIG
	if env := os.Getenv("RUSTYGO_CONFIG"); env != "" {
		return env, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, "config.json"), nil
}

// Load reads config.json and applies env-based overrides.
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
	cfg.fillFromEnv()
	return &cfg, nil
}

// fillFromEnv populates missing secrets from environment variables.
func (c *Config) fillFromEnv() {
	// Shodan
	if c.APIKeys.Shodan == "" {
		c.APIKeys.Shodan = os.Getenv("RUSTYGO_SHODAN_API_KEY")
	}
	// Censys
	if c.APIKeys.CensysID == "" {
		c.APIKeys.CensysID = os.Getenv("RUSTYGO_CENSYS_API_ID")
	}
	if c.APIKeys.CensysSecret == "" {
		c.APIKeys.CensysSecret = os.Getenv("RUSTYGO_CENSYS_API_SECRET")
	}
	// BinaryEdge
	if c.APIKeys.BinaryEdge == "" {
		c.APIKeys.BinaryEdge = os.Getenv("RUSTYGO_BINARYEDGE_API_KEY")
	}
	// ipinfo.io
	if c.APIKeys.IPInfoToken == "" {
		c.APIKeys.IPInfoToken = os.Getenv("RUSTYGO_IPINFO_TOKEN")
	}
	// urlscan.io
	if c.APIKeys.URLScanKey == "" {
		c.APIKeys.URLScanKey = os.Getenv("RUSTYGO_URLSCAN_API_KEY")
	}
	// VirusTotal
	if c.APIKeys.VirusTotal == "" {
		c.APIKeys.VirusTotal = os.Getenv("RUSTYGO_VT_API_KEY")
	}
	// Netlas
	if c.APIKeys.NetlasToken == "" {
		c.APIKeys.NetlasToken = os.Getenv("RUSTYGO_NETLAS_API_KEY")
	}
	// dnstwister
	if c.APIKeys.DNSTwister == "" {
		c.APIKeys.DNSTwister = os.Getenv("RUSTYGO_DNSTWISTER_API_KEY")
	}

	// Empire
	if c.APIKeys.EmpireAPIURL == "" {
		c.APIKeys.EmpireAPIURL = os.Getenv("RUSTYGO_EMPIRE_API_URL")
	}
	if c.APIKeys.EmpireUser == "" {
		c.APIKeys.EmpireUser = os.Getenv("RUSTYGO_EMPIRE_USER")
	}
	if c.APIKeys.EmpirePass == "" {
		c.APIKeys.EmpirePass = os.Getenv("RUSTYGO_EMPIRE_PASS")
	}
	if c.APIKeys.EmpireAPIToken == "" {
		c.APIKeys.EmpireAPIToken = os.Getenv("RUSTYGO_EMPIRE_API_TOKEN")
	}

	// Adaptix
	if c.APIKeys.AdaptixAPIURL == "" {
		c.APIKeys.AdaptixAPIURL = os.Getenv("RUSTYGO_ADAPTIX_API_URL")
	}
	if c.APIKeys.AdaptixUsername == "" {
		c.APIKeys.AdaptixUsername = os.Getenv("RUSTYGO_ADAPTIX_USERNAME")
	}
	if c.APIKeys.AdaptixPassword == "" {
		c.APIKeys.AdaptixPassword = os.Getenv("RUSTYGO_ADAPTIX_PASSWORD")
	}
}
