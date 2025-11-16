package web

import (
    "bufio"
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "strconv"
    "strings"

    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/executil"
    "github.com/MKlolbullen/rustygo/internal/model"
)

// ContentScanner wraps ffuf, feroxbuster and related tools.
type ContentScanner struct {
    cfg *config.Config
}

func NewContentScanner(cfg *config.Config) *ContentScanner {
    return &ContentScanner{cfg: cfg}
}

// ----------------- ffuf -----------------

// Ffuf runs ffuf against baseURL with the given wordlist.
// extraArgs can be used to pass additional ffuf flags.
func (c *ContentScanner) Ffuf(ctx context.Context, baseURL, wordlist string, extraArgs []string) ([]model.HTTPBruteResult, error) {
    if baseURL == "" || wordlist == "" {
        return nil, fmt.Errorf("baseURL and wordlist are required")
    }
    bin := c.cfg.ToolPaths.Ffuf
    if bin == "" {
        bin = "ffuf"
    }

    // ffuf -u https://site/FUZZ -w wordlist -of json -o -
    args := []string{
        "-u", strings.TrimRight(baseURL, "/") + "/FUZZ",
        "-w", wordlist,
        "-of", "json",
        "-o", "-",
    }
    args = append(args, extraArgs...)

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, fmt.Errorf("ffuf error: %w\nstderr: %s", res.Err, string(res.Stderr))
    }

    type ffufResult struct {
        Results []struct {
            URL    string `json:"url"`
            Status int    `json:"status"`
            Length int    `json:"length"`
            Words  int    `json:"words"`
            Lines  int    `json:"lines"`
            Method string `json:"method"`
        } `json:"results"`
    }

    var payload ffufResult
    if err := json.Unmarshal(res.Stdout, &payload); err != nil {
        return nil, fmt.Errorf("parse ffuf json: %w", err)
    }

    out := make([]model.HTTPBruteResult, 0, len(payload.Results))
    for _, r := range payload.Results {
        out = append(out, model.HTTPBruteResult{
            Tool:       "ffuf",
            URL:        r.URL,
            StatusCode: r.Status,
            Length:     r.Length,
            Words:      r.Words,
            Lines:      r.Lines,
            Method:     r.Method,
        })
    }
    return out, nil
}

// ----------------- feroxbuster -----------------

// Ferox runs feroxbuster in JSON mode and parses results.
func (c *ContentScanner) Ferox(ctx context.Context, baseURL string, extraArgs []string) ([]model.HTTPBruteResult, error) {
    if baseURL == "" {
        return nil, fmt.Errorf("baseURL is required")
    }
    bin := c.cfg.ToolPaths.Feroxbuster
    if bin == "" {
        bin = "feroxbuster"
    }

    // feroxbuster --json -u URL -q -o -  (JSON lines on stdout)
    args := []string{
        "--json",
        "-u", baseURL,
        "-q",
        "-o", "-",
    }
    args = append(args, extraArgs...)

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, fmt.Errorf("feroxbuster error: %w\nstderr: %s", res.Err, string(res.Stderr))
    }

    type feroxJSON struct {
        Url    string `json:"url"`
        Status int    `json:"status"`
        Length int    `json:"content_length"`
        Method string `json:"method"`
    }

    out := []model.HTTPBruteResult{}
    scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }
        var entry feroxJSON
        if err := json.Unmarshal([]byte(line), &entry); err != nil {
            continue
        }
        out = append(out, model.HTTPBruteResult{
            Tool:       "feroxbuster",
            URL:        entry.Url,
            StatusCode: entry.Status,
            Length:     entry.Length,
            Method:     entry.Method,
        })
    }
    return out, nil
}

// ----------------- whatweb -----------------

// Whatweb fingerprints a single URL.
func (c *ContentScanner) Whatweb(ctx context.Context, url string, extraArgs []string) (*model.WebTechInfo, error) {
    if url == "" {
        return nil, fmt.Errorf("url is required")
    }
    bin := c.cfg.ToolPaths.Whatweb
    if bin == "" {
        bin = "whatweb"
    }

    // whatweb --log-json=- URL
    args := []string{"--log-json=-", url}
    args = append(args, extraArgs...)

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, fmt.Errorf("whatweb error: %w\nstderr: %s", res.Err, string(res.Stderr))
    }

    // whatweb JSON is an array; keep it generic
    var raw []map[string]interface{}
    if err := json.Unmarshal(res.Stdout, &raw); err != nil {
        // fallback: just record raw text
        return &model.WebTechInfo{
            URL:          url,
            Technologies: nil,
            Raw:          map[string]interface{}{"raw": string(res.Stdout)},
        }, nil
    }

    techs := make(map[string]struct{})
    for _, entry := range raw {
        if name, ok := entry["name"].(string); ok && name != "" {
            techs[name] = struct{}{}
        }
    }
    techList := make([]string, 0, len(techs))
    for t := range techs {
        techList = append(techList, t)
    }

    return &model.WebTechInfo{
        URL:          url,
        Technologies: techList,
        Raw:          mapStringInterface(raw),
    }, nil
}

func mapStringInterface(v interface{}) map[string]interface{} {
    // Very cheap wrapper: we'll just store under "data".
    return map[string]interface{}{"data": v}
}

// ----------------- favirecon -----------------

// Favirecon runs favirecon against a URL and returns favicon hash.
// Since tools differ, we treat stdout as "hash path".
func (c *ContentScanner) Favirecon(ctx context.Context, url string, extraArgs []string) (*model.FaviconInfo, error) {
    if url == "" {
        return nil, fmt.Errorf("url is required")
    }
    bin := c.cfg.ToolPaths.Favirecon
    if bin == "" {
        bin = "favirecon"
    }
    args := []string{url}
    args = append(args, extraArgs...)

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, fmt.Errorf("favirecon error: %w\nstderr: %s", res.Err, string(res.Stderr))
    }

    // Very generic parse: try "hash path" or just "hash"
    out := strings.TrimSpace(string(res.Stdout))
    parts := strings.Fields(out)
    fi := &model.FaviconInfo{URL: url}
    if len(parts) > 0 {
        fi.Hash = parts[0]
    }
    if len(parts) > 1 {
        fi.IconPath = parts[1]
    }
    return fi, nil
}

// ----------------- csprecon -----------------

// Csprecon runs csprecon and parses a CSP for a single URL.
func (c *ContentScanner) Csprecon(ctx context.Context, url string, extraArgs []string) (*model.CSPInfo, error) {
    if url == "" {
        return nil, fmt.Errorf("url is required")
    }
    bin := c.cfg.ToolPaths.Csprecon
    if bin == "" {
        bin = "csprecon"
    }
    args := []string{url}
    args = append(args, extraArgs...)

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, fmt.Errorf("csprecon error: %w\nstderr: %s", res.Err, string(res.Stderr))
    }

    // Assume csprecon prints CSP header or JSON; we keep raw and do a simple split
    raw := strings.TrimSpace(string(res.Stdout))
    info := &model.CSPInfo{
        URL: url,
        Raw: raw,
    }
    directives := map[string][]string{}
    for _, part := range strings.Split(raw, ";") {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }
        kv := strings.Fields(part)
        if len(kv) == 0 {
            continue
        }
        dir := kv[0]
        vals := []string{}
        if len(kv) > 1 {
            vals = kv[1:]
        }
        directives[dir] = append(directives[dir], vals...)
    }
    info.Directives = directives
    return info, nil
}

// ----------------- nextnet -----------------

// Nextnet runs nextnet and just returns raw output as NetworkExposure.
func (c *ContentScanner) Nextnet(ctx context.Context, target string, extraArgs []string) (*model.NetworkExposure, error) {
    if target == "" {
        return nil, fmt.Errorf("target is required")
    }
    bin := c.cfg.ToolPaths.Nextnet
    if bin == "" {
        bin = "nextnet"
    }
    args := []string{target}
    args = append(args, extraArgs...)

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, fmt.Errorf("nextnet error: %w\nstderr: %s", res.Err, string(res.Stderr))
    }

    return &model.NetworkExposure{
        Target: target,
        Output: string(res.Stdout),
    }, nil
}

// Helper to parse integers safely
func parseInt(s string) int {
    s = strings.TrimSpace(s)
    if s == "" {
        return 0
    }
    n, _ := strconv.Atoi(s)
    return n
}
