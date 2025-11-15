package recon

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/executil"
	"github.com/MKlolbullen/rustygo/internal/model"
)

type DNSOptions struct {
	Records []string // e.g. A,AAAA,CNAME,TXT,SRV,SOA,NS,MX
}

type DNSEngine struct {
	cfg *config.Config
}

func NewDNSEngine(cfg *config.Config) *DNSEngine {
	return &DNSEngine{cfg: cfg}
}

// Given subdomains, resolve them with dnsx and return parsed records
func (e *DNSEngine) Resolve(ctx context.Context, subs []model.Subdomain, opts DNSOptions) ([]model.DNSRecord, error) {
	if len(subs) == 0 {
		return nil, nil
	}
	bin := "dnsx" // for now; you can add to config.ToolPaths later

	args := []string{"-resp-only", "-json"}

	if len(opts.Records) > 0 {
		args = append(args, "-t", strings.Join(opts.Records, ","))
	}

	// dnsx reads stdin list of hosts
	stdin := &strings.Builder{}
	for _, s := range subs {
		stdin.WriteString(s.Name)
		stdin.WriteByte('\n')
	}

	res := executil.RunWithStdin(ctx, bin, stdin.String(), args...)
	if res.Err != nil {
		return nil, res.Err
	}

	// dnsx JSON schema is flexible; we’ll parse minimally
	type dnsxOut struct {
		Host   string   `json:"host"`
		Answer []string `json:"answer,omitempty"`
		A      []string `json:"a,omitempty"`
		Aaaa   []string `json:"aaaa,omitempty"`
		Cname  []string `json:"cname,omitempty"`
		Txt    []string `json:"txt,omitempty"`
		Mx     []string `json:"mx,omitempty"`
		Ns     []string `json:"ns,omitempty"`
		// etc…
	}

	scanner := bufio.NewScanner(strings.NewReader(string(res.Stdout)))
	var out []model.DNSRecord

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var o dnsxOut
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			continue
		}
		now := time.Now().UTC()
		_ = now // not used in struct, but you can expand later

		if len(o.A) > 0 {
			out = append(out, model.DNSRecord{Name: o.Host, Type: "A", Value: o.A})
		}
		if len(o.Aaaa) > 0 {
			out = append(out, model.DNSRecord{Name: o.Host, Type: "AAAA", Value: o.Aaaa})
		}
		if len(o.Cname) > 0 {
			out = append(out, model.DNSRecord{Name: o.Host, Type: "CNAME", Value: o.Cname})
		}
		if len(o.Txt) > 0 {
			out = append(out, model.DNSRecord{Name: o.Host, Type: "TXT", Value: o.Txt})
		}
		if len(o.Mx) > 0 {
			out = append(out, model.DNSRecord{Name: o.Host, Type: "MX", Value: o.Mx})
		}
		if len(o.Ns) > 0 {
			out = append(out, model.DNSRecord{Name: o.Host, Type: "NS", Value: o.Ns})
		}
	}
	return out, scanner.Err()
}
