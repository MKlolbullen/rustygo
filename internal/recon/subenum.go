package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/executil"
)

type SubenumTool string

const (
	ToolSubfinder   SubenumTool = "subfinder"
	ToolAssetfinder SubenumTool = "assetfinder"
	ToolCRTSh       SubenumTool = "crtsh"
)

type SubenumOptions struct {
	Domain string
	Tools  []SubenumTool
}

type SubdomainResult struct {
	Domain     string    `json:"domain"`
	Source     string    `json:"source"`
	Raw        string    `json:"raw,omitempty"`
	Discovered time.Time `json:"discovered"`
}

type SubenumEngine struct {
	cfg *config.Config
}

func NewSubenumEngine(cfg *config.Config) *SubenumEngine {
	return &SubenumEngine{cfg: cfg}
}

func (e *SubenumEngine) Run(ctx context.Context, opts SubenumOptions) ([]SubdomainResult, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if len(opts.Tools) == 0 {
		opts.Tools = []SubenumTool{ToolSubfinder, ToolAssetfinder}
	}

	var wg sync.WaitGroup
	resCh := make(chan SubdomainResult, 1024)
	errCh := make(chan error, len(opts.Tools))

	for _, t := range opts.Tools {
		wg.Add(1)
		go func(tool SubenumTool) {
			defer wg.Done()
			if err := e.runTool(ctx, tool, opts.Domain, resCh); err != nil {
				errCh <- fmt.Errorf("%s: %w", tool, err)
			}
		}(t)
	}

	go func() {
		wg.Wait()
		close(resCh)
		close(errCh)
	}()

	seen := make(map[string]bool)
	var all []SubdomainResult

	for r := range resCh {
		key := strings.ToLower(r.Domain)
		if !seen[key] {
			seen[key] = true
			all = append(all, r)
		}
	}

	for err := range errCh {
		if err != nil {
			return all, err
		}
	}

	return all, nil
}

func (e *SubenumEngine) runTool(ctx context.Context, tool SubenumTool, domain string, out chan<- SubdomainResult) error {
	switch tool {
	case ToolSubfinder:
		return e.runSubfinder(ctx, domain, out)
	case ToolAssetfinder:
		return e.runAssetfinder(ctx, domain, out)
	case ToolCRTSh:
		return e.runCRTSh(ctx, domain, out)
	default:
		return fmt.Errorf("unsupported tool: %s", tool)
	}
}

func (e *SubenumEngine) runSubfinder(ctx context.Context, domain string, out chan<- SubdomainResult) error {
	bin := e.cfg.ToolPaths.Subfinder
	if bin == "" {
		bin = "subfinder"
	}
	args := []string{"-silent", "-d", domain}
	res := executil.Run(ctx, bin, args...)
	if res.Err != nil {
		return res.Err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(res.Stdout)))
	now := time.Now().UTC()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out <- SubdomainResult{
			Domain:     line,
			Source:     "subfinder",
			Raw:        line,
			Discovered: now,
		}
	}
	return scanner.Err()
}

func (e *SubenumEngine) runAssetfinder(ctx context.Context, domain string, out chan<- SubdomainResult) error {
	bin := e.cfg.ToolPaths.Assetfinder
	if bin == "" {
		bin = "assetfinder"
	}

	res := executil.Run(ctx, bin, domain)
	if res.Err != nil {
		return res.Err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(res.Stdout)))
	now := time.Now().UTC()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, "."+domain) && line != domain {
			continue
		}
		out <- SubdomainResult{
			Domain:     line,
			Source:     "assetfinder",
			Raw:        line,
			Discovered: now,
		}
	}
	return scanner.Err()
}

func (e *SubenumEngine) runCRTSh(ctx context.Context, domain string, out chan<- SubdomainResult) error {
	u := "https://crt.sh/"
	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")

	req, err := http.NewRequestWithContext(ctx, "GET", u+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("crt.sh: unexpected status %s", resp.Status)
	}

	var records []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, r := range records {
		for _, host := range strings.Split(r.NameValue, "\n") {
			host = strings.TrimSpace(host)
			if host == "" || !strings.HasSuffix(host, "."+domain) {
				continue
			}
			out <- SubdomainResult{
				Domain:     host,
				Source:     "crt.sh",
				Raw:        r.NameValue,
				Discovered: now,
			}
		}
	}
	return nil
}
