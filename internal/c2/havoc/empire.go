package c2

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"

    "github.com/MKlolbullen/rustygo/internal/config"
)

// EmpireClient wraps the PowerShell Empire REST API.
type EmpireClient struct {
    baseURL string
    user    string
    pass    string
    token   string
}

type EmpireConfig struct {
    APIURL   string
    Username string
    Password string
    APIToken string
}

func NewEmpireClient(cfg EmpireConfig) *EmpireClient {
    return &EmpireClient{
        baseURL: strings.TrimRight(cfg.APIURL, "/"),
        user:    cfg.Username,
        pass:    cfg.Password,
        token:   cfg.APIToken,
    }
}

func (c *EmpireClient) Login() error {
    if c.token != "" {
        return nil
    }
    authURL := c.baseURL + "/api/admin/login"
    data := url.Values{}
    data.Set("username", c.user)
    data.Set("password", c.pass)

    resp, err := http.PostForm(authURL, data)
    if err != nil {
        return fmt.Errorf("empire login: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("empire login failed: %s: %s", resp.Status, string(body))
    }

    var payload struct {
        Token string `json:"token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
        return fmt.Errorf("empire login decode: %w", err)
    }
    c.token = payload.Token
    return nil
}

func (c *EmpireClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
    req, err := http.NewRequest(method, c.baseURL+path, body)
    if err != nil {
        return nil, err
    }
    if c.token != "" {
        req.Header.Set("Authorization", "Bearer "+c.token)
    }
    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }
    return http.DefaultClient.Do(req)
}

// GenerateStagerFromConfig is a high-level helper that, given a config map
// describing listener/stager parameters, ensures a listener exists and returns
// the generated stager code.
func (c *EmpireClient) GenerateStagerFromConfig(cfg map[string]interface{}) (string, string, error) {
    // Simplified example: cfg["listener_name"], cfg["listener_type"], cfg["stager_name"], cfg["stager_type"]
    listenerName, _ := cfg["listener_name"].(string)
    if listenerName == "" {
        listenerName = "rustygo-listener"
    }

    // Ensure listener exists
    if err := c.ensureListener(listenerName, cfg); err != nil {
        return "", "", err
    }

    // Generate stager
    stagerName, _ := cfg["stager_name"].(string)
    if stagerName == "" {
        stagerName = "rustygo-stager"
    }
    stagerType, _ := cfg["stager_type"].(string)
    if stagerType == "" {
        stagerType = "multi/launcher"
    }

    stagerCode, err := c.createStager(stagerName, stagerType, listenerName)
    if err != nil {
        return "", "", err
    }
    return listenerName, stagerCode, nil
}

func (c *EmpireClient) ensureListener(name string, cfg map[string]interface{}) error {
    // Minimal stub: in a real integration, this would check existing listeners
    // and create one via /api/listeners if missing.
    return nil
}

func (c *EmpireClient) createStager(name, stype, listener string) (string, error) {
    body := map[string]interface{}{
        "Name":     name,
        "Listener": listener,
        "Stager":   stype,
    }
    data, err := json.Marshal(body)
    if err != nil {
        return "", err
    }
    resp, err := c.doRequest("POST", "/api/stagers", bytes.NewBuffer(data))
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        return "", fmt.Errorf("create stager: %s: %s", resp.Status, string(b))
    }
    var out struct {
        Code string `json:"Code"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return "", err
    }
    return out.Code, nil
}

// ConfigFromGlobal constructs an EmpireConfig from the global configuration.
func ConfigFromGlobal(cfg *config.Config) EmpireConfig {
    return EmpireConfig{
        APIURL:   cfg.APIKeys.EmpireAPIURL,
        Username: cfg.APIKeys.EmpireUser,
        Password: cfg.APIKeys.EmpirePass,
        APIToken: cfg.APIKeys.EmpireAPIToken,
    }
}
