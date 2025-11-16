package osint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MKlolbullen/rustygo/internal/config"
)

// simple HTTP client with timeout
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
	}
}

// ------------- Shodan -------------

type ShodanClient struct {
	APIKey   string
	BaseURL  string
	httpClient *http.Client
}

func NewShodanClient(cfg *config.Config) *ShodanClient {
	key := cfg.APIKeys.Shodan
	if key == "" {
		return nil
	}
	return &ShodanClient{
		APIKey:   key,
		BaseURL:  "https://api.shodan.io",
		httpClient: defaultHTTPClient(),
	}
}

// ShodanHostResponse is intentionally generic.
type ShodanHostResponse map[string]interface{}

// LookupHost calls /shodan/host/{ip}
func (c *ShodanClient) LookupHost(ctx context.Context, ip string) (ShodanHostResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("shodan client not configured")
	}
	u := fmt.Sprintf("%s/shodan/host/%s?key=%s", c.BaseURL, url.PathEscape(ip), url.QueryEscape(c.APIKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("shodan error: %s: %s", resp.Status, string(body))
	}
	var out ShodanHostResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ------------- Censys -------------

type CensysClient struct {
	ID     string
	Secret string
	BaseURL string
	httpClient *http.Client
}

func NewCensysClient(cfg *config.Config) *CensysClient {
	id := cfg.APIKeys.CensysID
	sec := cfg.APIKeys.CensysSecret
	if id == "" || sec == "" {
		return nil
	}
	return &CensysClient{
		ID:     id,
		Secret: sec,
		// For newer APIs you might want "https://search.censys.io/api/v2"
		BaseURL:    "https://search.censys.io/api/v2",
		httpClient: defaultHTTPClient(),
	}
}

// CensysSearchHosts performs a generic host search.
// The exact path/shape may need adjustment per API version.
func (c *CensysClient) SearchHosts(ctx context.Context, query string) (map[string]interface{}, error) {
	if c == nil {
		return nil, fmt.Errorf("censys client not configured")
	}
	endpoint := c.BaseURL + "/hosts/search"
	body := map[string]interface{}{
		"q": query,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(c.ID + ":" + c.Secret))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("censys error: %s: %s", resp.Status, string(b))
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ------------- BinaryEdge -------------

type BinaryEdgeClient struct {
	APIKey  string
	BaseURL string
	httpClient *http.Client
}

func NewBinaryEdgeClient(cfg *config.Config) *BinaryEdgeClient {
	key := cfg.APIKeys.BinaryEdge
	if key == "" {
		return nil
	}
	return &BinaryEdgeClient{
		APIKey:  key,
		BaseURL: "https://api.binaryedge.io/v2",
		httpClient: defaultHTTPClient(),
	}
}

// IPInfo fetches IP info from BinaryEdge, mapping is generic.
func (c *BinaryEdgeClient) IPInfo(ctx context.Context, ip string) (map[string]interface{}, error) {
	if c == nil {
		return nil, fmt.Errorf("binaryedge client not configured")
	}
	u := fmt.Sprintf("%s/query/ip/%s", c.BaseURL, url.PathEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Key", c.APIKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("binaryedge error: %s: %s", resp.Status, string(b))
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ------------- ipinfo.io -------------

type IPInfoClient struct {
	Token    string
	BaseURL  string
	httpClient *http.Client
}

func NewIPInfoClient(cfg *config.Config) *IPInfoClient {
	t := cfg.APIKeys.IPInfoToken
	if t == "" {
		return nil
	}
	return &IPInfoClient{
		Token:   t,
		BaseURL: "https://ipinfo.io",
		httpClient: defaultHTTPClient(),
	}
}

// IPInfoResponse is generic ipinfo output.
type IPInfoResponse map[string]interface{}

func (c *IPInfoClient) LookupIP(ctx context.Context, ip string) (IPInfoResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("ipinfo client not configured")
	}
	u := fmt.Sprintf("%s/%s/json?token=%s", c.BaseURL, url.PathEscape(ip), url.QueryEscape(c.Token))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ipinfo error: %s: %s", resp.Status, string(b))
	}
	var out IPInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ------------- urlscan.io -------------

type URLScanClient struct {
	APIKey  string
	BaseURL string
	httpClient *http.Client
}

func NewURLScanClient(cfg *config.Config) *URLScanClient {
	key := cfg.APIKeys.URLScanKey
	if key == "" {
		return nil
	}
	return &URLScanClient{
		APIKey:  key,
		BaseURL: "https://urlscan.io/api/v1",
		httpClient: defaultHTTPClient(),
	}
}

type URLScanSubmission struct {
	URL     string            `json:"url"`
	Custom  map[string]string `json:"custom,omitempty"`
	Tags    []string          `json:"tags,omitempty"`
	Private bool              `json:"private,omitempty"`
}

type URLScanSubmitResponse struct {
	UUID string `json:"uuid"`
}

// SubmitURL sends a URL to urlscan.io for scanning.
func (c *URLScanClient) SubmitURL(ctx context.Context, sub URLScanSubmission) (*URLScanSubmitResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("urlscan client not configured")
	}
	data, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	u := c.BaseURL + "/scan/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("urlscan error: %s: %s", resp.Status, string(b))
	}
	var out URLScanSubmitResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetResult retrieves a scan result by UUID.
func (c *URLScanClient) GetResult(ctx context.Context, uuid string) (map[string]interface{}, error) {
	if c == nil {
		return nil, fmt.Errorf("urlscan client not configured")
	}
	u := fmt.Sprintf("%s/result/%s", c.BaseURL, url.PathEscape(uuid))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("urlscan result error: %s: %s", resp.Status, string(b))
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ------------- VirusTotal -------------

type VirusTotalClient struct {
	APIKey  string
	BaseURL string
	httpClient *http.Client
}

func NewVirusTotalClient(cfg *config.Config) *VirusTotalClient {
	k := cfg.APIKeys.VirusTotal
	if k == "" {
		return nil
	}
	return &VirusTotalClient{
		APIKey:  k,
		BaseURL: "https://www.virustotal.com/api/v3",
		httpClient: defaultHTTPClient(),
	}
}

func (c *VirusTotalClient) get(ctx context.Context, path string, query map[string]string) (map[string]interface{}, error) {
	if c == nil {
		return nil, fmt.Errorf("virustotal client not configured")
	}
	u, err := url.Parse(c.BaseURL + path)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", c.APIKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("virustotal error: %s: %s", resp.Status, string(b))
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// LookupDomain looks up a domain in VirusTotal.
func (c *VirusTotalClient) LookupDomain(ctx context.Context, domain string) (map[string]interface{}, error) {
	return c.get(ctx, "/domains/"+url.PathEscape(domain), nil)
}

// LookupURL looks up a URL (VT v3 expects URL identifier form).
func (c *VirusTotalClient) LookupURL(ctx context.Context, id string) (map[string]interface{}, error) {
	return c.get(ctx, "/urls/"+url.PathEscape(id), nil)
}

// LookupIP looks up an IP address.
func (c *VirusTotalClient) LookupIP(ctx context.Context, ip string) (map[string]interface{}, error) {
	return c.get(ctx, "/ip_addresses/"+url.PathEscape(ip), nil)
}

// ------------- Netlas -------------

type NetlasClient struct {
	APIKey  string
	BaseURL string
	httpClient *http.Client
}

func NewNetlasClient(cfg *config.Config) *NetlasClient {
	k := cfg.APIKeys.NetlasToken
	if k == "" {
		return nil
	}
	return &NetlasClient{
		APIKey:  k,
		BaseURL: "https://app.netlas.io/api",
		httpClient: defaultHTTPClient(),
	}
}

// Search performs a generic Netlas search.
// Exact endpoint/type can be tuned ("/responses", "/domains", etc).
func (c *NetlasClient) Search(ctx context.Context, index, query string) (map[string]interface{}, error) {
	if c == nil {
		return nil, fmt.Errorf("netlas client not configured")
	}
	endpoint := fmt.Sprintf("%s/%s/search", c.BaseURL, index)
	body := map[string]interface{}{
		"query": query,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("netlas error: %s: %s", resp.Status, string(b))
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ------------- dnstwister -------------

type DNSTwisterClient struct {
	APIKey  string
	BaseURL string
	httpClient *http.Client
}

func NewDNSTwisterClient(cfg *config.Config) *DNSTwisterClient {
	k := cfg.APIKeys.DNSTwister
	// Some dnstwister deployments don’t need a key; you can allow empty.
	return &DNSTwisterClient{
		APIKey:  k,
		BaseURL: "https://dnstwister.report/api",
		httpClient: defaultHTTPClient(),
	}
}

// Typos generates domain permutations.
// Exact path may differ by deployment; adjust as needed.
func (c *DNSTwisterClient) Typos(ctx context.Context, domain string) (map[string]interface{}, error) {
	if c == nil {
		return nil, fmt.Errorf("dnstwister client not configured")
	}
	u := fmt.Sprintf("%s/twist/%s", c.BaseURL, url.PathEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("dnstwister error: %s: %s", resp.Status, string(b))
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
