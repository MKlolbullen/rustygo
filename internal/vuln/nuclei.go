package vuln

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/MKlolbullen/rustygo/internal/executil"
	"github.com/MKlolbullen/rustygo/internal/model"
)

type NucleiOptions struct {
	Templates string   // e.g. "cves,exposures" or path
	Severity  []string // e.g. [ "high", "critical" ]
	Tags      []string
}

type NucleiEngine struct{}

func NewNucleiEngine() *NucleiEngine { return &NucleiEngine{} }

func (e *NucleiEngine) Scan(ctx context.Context, urls []string, opts NucleiOptions) ([]model.VulnFinding, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	args := []string{"-json", "-silent"}

	if opts.Templates != "" {
		args = append(args, "-templates", opts.Templates)
	}
	if len(opts.Severity) > 0 {
		args = append(args, "-severity", strings.Join(opts.Severity, ","))
	}
	if len(opts.Tags) > 0 {
		args = append(args, "-tags", strings.Join(opts.Tags, ","))
	}

	stdin := strings.Join(urls, "\n") + "\n"

	res := executil.RunWithStdin(ctx, stdin, "nuclei", args...)
	if res.Err != nil {
		return nil, res.Err
	}

	type nucleiOut struct {
		TemplateID string   `json:"template-id"`
		Info       struct {
			Name     string   `json:"name"`
			Severity string   `json:"severity"`
			Tags     []string `json:"tags"`
		} `json:"info"`
		Host string `json:"host"`
		Matched string `json:"matched-at"`
	}

	scanner := bufio.NewScanner(strings.NewReader(string(res.Stdout)))
	var out []model.VulnFinding
	now := time.Now().UTC()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var o nucleiOut
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			continue
		}
		out = append(out, model.VulnFinding{
			ID:        o.TemplateID,
			Template:  o.Info.Name,
			Severity:  o.Info.Severity,
			Target:    o.Matched,
			Tags:      o.Info.Tags,
			Raw:       line,
			DetectedAt: now,
		})
	}
	return out, scanner.Err()
    }
