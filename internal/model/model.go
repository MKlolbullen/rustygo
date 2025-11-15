package model

import "time"

type Subdomain struct {
	Name       string    `json:"name"`
	Source     string    `json:"source"`
	Discovered time.Time `json:"discovered"`
}

type DNSRecord struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

type HTTPService struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title,omitempty"`
	Technologies []string          `json:"technologies,omitempty"` // from httpx or wappalyzer-like
	Headers      map[string]string `json:"headers,omitempty"`
}

type Port struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
}

// A “workspace” or “target run” that the GUI can show
type ReconResult struct {
	Domain     string        `json:"domain"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt *time.Time    `json:"finished_at,omitempty"`
	Subdomains []Subdomain   `json:"subdomains"`
	DNS        []DNSRecord   `json:"dns"`
	Ports      []Port        `json:"ports"`
	HTTP       []HTTPService `json:"http"`
	Vulns      []VulnFinding `json:"vulns"`
}

type VulnFinding struct {
	ID        string   `json:"id"`
	Template  string   `json:"template"`
	Severity  string   `json:"severity"`
	Target    string   `json:"target"`
	Tags      []string `json:"tags,omitempty"`
	Raw       string   `json:"raw,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
}
