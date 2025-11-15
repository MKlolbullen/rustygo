package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/MKlolbullen/rustygo/internal/executil"
	"github.com/MKlolbullen/rustygo/internal/model"
)

type HTTPEngine struct{}

func NewHTTPEngine() *HTTPEngine { return &HTTPEngine{} }

type httpxOut struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Title      string            `json:"title,omitempty"`
	Tech       []string          `json:"tech,omitempty"`     // depending on flags
	Headers    map[string]string `json:"headers,omitempty"`  // optional
}

func (e *HTTPEngine) Probe(ctx context.Context, subs []model.Subdomain, ports []int) ([]model.HTTPService, error) {
	if len(subs) == 0 {
		return nil, nil
	}
	bin := "httpx"

	args := []string{
		"-json",
		"-title",
		"-status-code",
		"-tech-detect",
		"-silent",
	}
	if len(ports) > 0 {
		portStr := make([]string, len(ports))
		for i, p := range ports {
			portStr[i] = strconv.Itoa(p)
		}
		args = append(args, "-ports", strings.Join(portStr, ","))
	}

	stdin := &strings.Builder{}
	for _, s := range subs {
		stdin.WriteString(s.Name)
		stdin.WriteByte('\n')
	}

	res := executil.RunWithStdin(ctx, stdin.String(), bin, args...)
	if res.Err != nil {
		return nil, res.Err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(res.Stdout)))
	var out []model.HTTPService
	now := time.Now().UTC()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var o httpxOut
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			continue
		}
		svc := model.HTTPService{
			URL:          o.URL,
			StatusCode:   o.StatusCode,
			Title:        o.Title,
			Technologies: o.Tech,
			Headers:      o.Headers,
		}
		_ = now // reserved for future; we can add a timestamp later
		out = append(out, svc)
	}
	return out, scanner.Err()
}
