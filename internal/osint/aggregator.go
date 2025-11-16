package osint

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/model"
)

// Aggregator calls all configured OSINT providers in parallel and
// merges their outputs into unified enrichment structs.
type Aggregator struct {
	shodan     *ShodanClient
	censys     *CensysClient
	binaryedge *BinaryEdgeClient
	ipinfo     *IPInfoClient
	urlscan    *URLScanClient
	vt         *VirusTotalClient
	netlas     *NetlasClient
	dnstwister *DNSTwisterClient
}

// NewAggregator builds an Aggregator from global config. Any provider
// without an API key will simply be nil and skipped.
func NewAggregator(cfg *config.Config) *Aggregator {
	if cfg == nil {
		return nil
	}
	return &Aggregator{
		shodan:     NewShodanClient(cfg),
		censys:     NewCensysClient(cfg),
		binaryedge: NewBinaryEdgeClient(cfg),
		ipinfo:     NewIPInfoClient(cfg),
		urlscan:    NewURLScanClient(cfg),
		vt:         NewVirusTotalClient(cfg),
		netlas:     NewNetlasClient(cfg),
		dnstwister: NewDNSTwisterClient(cfg),
	}
}

// EnrichIP collects OSINT for a single IP across Shodan, Censys, BinaryEdge,
// ipinfo, VirusTotal and Netlas. It returns best-effort results even if some
// providers fail, with per-provider errors in IPEnrichment.Errors.
func (a *Aggregator) EnrichIP(ctx context.Context, ip string) (*model.IPEnrichment, error) {
	if a == nil {
		return nil, fmt.Errorf("aggregator is nil")
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}

	enr := &model.IPEnrichment{
		IP:     ip,
		Errors: make(map[string]string),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Shodan
	if a.shodan != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.shodan.LookupHost(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["shodan"] = err.Error()
				return
			}
			enr.Shodan = res
		}()
	}

	// Censys (very simple query: ip:x.x.x.x)
	if a.censys != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.censys.SearchHosts(ctx, fmt.Sprintf("ip:%s", ip))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["censys"] = err.Error()
				return
			}
			enr.Censys = res
		}()
	}

	// BinaryEdge
	if a.binaryedge != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.binaryedge.IPInfo(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["binaryedge"] = err.Error()
				return
			}
			enr.BinaryEdge = res
		}()
	}

	// ipinfo.io
	if a.ipinfo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.ipinfo.LookupIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["ipinfo"] = err.Error()
				return
			}
			enr.IPInfo = res
		}()
	}

	// VirusTotal
	if a.vt != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.vt.LookupIP(ctx, ip)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["virustotal"] = err.Error()
				return
			}
			enr.VirusTotal = res
		}()
	}

	// Netlas (responses index for IP/port-level data)
	if a.netlas != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := fmt.Sprintf("ip:\"%s\"", ip)
			res, err := a.netlas.Search(ctx, "responses", q)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["netlas"] = err.Error()
				return
			}
			enr.Netlas = res
		}()
	}

	wg.Wait()

	// If literally nothing succeeded, bubble up a hard error.
	if enr.Shodan == nil &&
		enr.Censys == nil &&
		enr.BinaryEdge == nil &&
		enr.IPInfo == nil &&
		enr.VirusTotal == nil &&
		enr.Netlas == nil {
		if len(enr.Errors) == 0 {
			return nil, fmt.Errorf("no providers configured for IP enrichment")
		}
		return nil, fmt.Errorf("no providers succeeded: %v", enr.Errors)
	}

	return enr, nil
}

// EnrichDomain collects OSINT for a domain across urlscan, VirusTotal,
// Netlas and dnstwister. For urlscan, it submits a new scan and returns
// the submission UUID (results can be fetched later).
func (a *Aggregator) EnrichDomain(ctx context.Context, domain string) (*model.DomainEnrichment, error) {
	if a == nil {
		return nil, fmt.Errorf("aggregator is nil")
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	enr := &model.DomainEnrichment{
		Domain: domain,
		Errors: make(map[string]string),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// urlscan.io: submit a scan for https://domain
	if a.urlscan != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := domain
			if !strings.Contains(u, "://") {
				u = "https://" + u
			}
			sub := URLScanSubmission{
				URL:     u,
				Private: true,
			}
			res, err := a.urlscan.SubmitURL(ctx, sub)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["urlscan"] = err.Error()
				return
			}
			enr.URLScan = map[string]interface{}{
				"uuid": res.UUID,
				"url":  u,
			}
		}()
	}

	// VirusTotal domain report
	if a.vt != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.vt.LookupDomain(ctx, domain)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["virustotal"] = err.Error()
				return
			}
			enr.VirusTotal = res
		}()
	}

	// Netlas domain index
	if a.netlas != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := fmt.Sprintf("domain:\"%s\"", domain)
			res, err := a.netlas.Search(ctx, "domains", q)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["netlas"] = err.Error()
				return
			}
			enr.Netlas = res
		}()
	}

	// dnstwister typosquatting permutations
	if a.dnstwister != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.dnstwister.Typos(ctx, domain)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				enr.Errors["dnstwister"] = err.Error()
				return
			}
			enr.DNSTwister = res
		}()
	}

	wg.Wait()

	if enr.URLScan == nil &&
		enr.VirusTotal == nil &&
		enr.Netlas == nil &&
		enr.DNSTwister == nil {
		if len(enr.Errors) == 0 {
			return nil, fmt.Errorf("no providers configured for domain enrichment")
		}
		return nil, fmt.Errorf("no providers succeeded: %v", enr.Errors)
	}

	return enr, nil
}
