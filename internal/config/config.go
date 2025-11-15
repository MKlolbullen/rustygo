package config

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
)

// ToolPaths holds absolute paths to external binaries. If empty, PATH will be used.
type ToolPaths struct {
    Subfinder   string `json:"subfinder"`
    Assetfinder string `json:"assetfinder"`
    Dnsx        string `json:"dnsx"`
    Httpx       string `json:"httpx"`
    Naabu       string `json:"naabu"`
    Nuclei      string `json:"nuclei"`

    // Enum4Linux is the path to the enum4linux-ng binary used for SMB/Windows
    // enumeration.
    Enum4linux string `json:"enum4linux_ng"`

    // Nbtstat is the path to the NetBIOS enumeration tool. This may refer to
    // either the `nbtstat` binary (on Windows) or `nbtscan` (on Unix-like
    // systems).
    Nbtstat string `json:"nbtstat"`

    // Netexec is the path to the netexec binary, used for advanced SMB/WinRM
    // enumeration.
    Netexec string `json:"netexec"`

    // HavocClient is the path to the Havoc C2 client binary, used for local
    // beacon generation/payload creation.
    HavocClient string `json:"havoc_client"`
}

// APIKeys holds API credentials and URLs for various services.
type APIKeys struct {
    Shodan       string `json:"shodan"`
    CensysID     string `json:"censys_id"`
    CensysSecret string `json:"censys_secret"`
    // Additional services like Netlas, FOFA, BinaryEdge can be added here.

    // Empire API configuration for interacting with PowerShell Empire via its
    // REST interface. When using the Starkiller GUI or Empire API, these
    // credentials allow the framework to programmatically generate listeners
    // and stagers.
    EmpireAPIURL  string `json:"empire_api_url"`
    EmpireUser    string `json:"empire_user"`
    EmpirePass    string `json:"empire_pass"`
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

func DefaultConfigPath() (string, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return "", err
    }
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