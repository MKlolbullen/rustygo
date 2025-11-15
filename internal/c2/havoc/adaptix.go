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

// AdaptixClient wraps the Adaptix C2 REST API.
type AdaptixClient struct {
    apiURL string
    user   string
    pass   string
    token  string
}

type AdaptixConfig struct {
    APIURL   string
    Username string
    Password string
}

func NewAdaptixClient(cfg AdaptixConfig) *AdaptixClient {
    return &AdaptixClient{
        apiURL: strings.TrimRight(cfg.APIURL, "/"),
        user:   cfg.Username,
        pass:   cfg.Password,
    }
}

func (c *AdaptixClient) Login() error {
    loginURL := c.apiURL + "/login"
    body := url.Values{}
    body.Set("username", c.user)
    body.Set("password", c.pass)
    resp, err := http.PostForm(loginURL, body)
    if err != nil {
        return fmt.Errorf("adaptix login: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("adaptix login: unexpected status %s", resp.Status)
    }
    var payload struct {
        Token string `json:"token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
        return fmt.Errorf("adaptix login decode: %w", err)
    }
    c.token = payload.Token
    return nil
}

func (c *AdaptixClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
    req, err := http.NewRequest(method, c.apiURL+path, body)
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

// GenerateAgent requests Adaptix to build a new agent.
// config map includes things like listener, format, etc.
func (c *AdaptixClient) GenerateAgent(cfg map[string]interface{}) (string, string, error) {
    data, err := json.Marshal(cfg)
    if err != nil {
        return "", "", err
    }
    resp, err := c.doRequest("POST", "/agents", bytes.NewBuffer(data))
    if err != nil {
        return "", "", err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusCreated {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return "", "", fmt.Errorf("adaptix generate agent: %s: %s", resp.Status, string(bodyBytes))
    }
    var out struct {
        ID  string `json:"id"`
        URL string `json:"url"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return "", "", err
    }
    return out.ID, out.URL, nil
}

// AdaptixConfigFromGlobal constructs an AdaptixConfig from the global configuration.
func AdaptixConfigFromGlobal(cfg *config.Config) AdaptixConfig {
    return AdaptixConfig{
        APIURL:   cfg.APIKeys.AdaptixAPIURL,
        Username: cfg.APIKeys.AdaptixUsername,
        Password: cfg.APIKeys.AdaptixPassword,
    }
}
