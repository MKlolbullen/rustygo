package pipeline

import (
	"context"
	"time"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/model"
	"github.com/MKlolbullen/rustygo/internal/recon"
	"github.com/MKlolbullen/rustygo/internal/scan"
	"github.com/MKlolbullen/rustygo/internal/vuln"
)

type FullPipeline struct {
	cfg *config.Config
}

func NewFullPipeline(cfg *config.Config) *FullPipeline {
	return &FullPipeline{cfg: cfg}
}

type FullOptions struct {
	Domain string
}

func (p *FullPipeline) Run(ctx context.Context, opts FullOptions) (*model.ReconResult, error) {
	start := time.Now().UTC()
	res := &model.ReconResult{
		Domain:    opts.Domain,
		StartedAt: start,
	}

	// 1) Subdomains
	subEngine := recon.NewSubenumEngine(p.cfg)
	subs, err := subEngine.Run(ctx, recon.SubenumOptions{
		Domain: opts.Domain,
	})
	if err != nil {
		return res, err
	}
	for _, s := range subs {
		res.Subdomains = append(res.Subdomains, model.Subdomain{
			Name:       s.Domain,
			Source:     s.Source,
			Discovered: s.Discovered,
		})
	}

	// 2) DNS
	dnsEngine := recon.NewDNSEngine(p.cfg)
	dnsRecords, _ := dnsEngine.Resolve(ctx, res.Subdomains, recon.DNSOptions{
		Records: []string{"A", "AAAA", "CNAME", "TXT", "NS", "MX"},
	})
	res.DNS = dnsRecords

	// host list for port scan
	hostSet := map[string]struct{}{}
	for _, d := range res.Subdomains {
		hostSet[d.Name] = struct{}{}
	}
	var hosts []string
	for h := range hostSet {
		hosts = append(hosts, h)
	}

	// 3) Ports
	portScanner := scan.NewPortScanner()
	ports, _ := portScanner.ScanNaabu(ctx, hosts, scan.NaabuOptions{
		Ports: "80,443,8080,8443,8000-8100",
		Rate:  10000,
	})
	res.Ports = ports

	// 4) HTTP services
	httpEngine := recon.NewHTTPEngine()
	httpServices, _ := httpEngine.Probe(ctx, res.Subdomains, []int{80, 443, 8080, 8443})
	res.HTTP = httpServices

	// 5) Vulnerabilities via Nuclei on HTTP URLs
	var urls []string
	for _, h := range res.HTTP {
		urls = append(urls, h.URL)
	}
	nuclei := vuln.NewNucleiEngine()
	vulns, _ := nuclei.Scan(ctx, urls, vuln.NucleiOptions{
		Severity: []string{"high", "critical"},
	})
	res.Vulns = vulns

	finish := time.Now().UTC()
	res.FinishedAt = &finish
	return res, nil
}
