package model

import "time"

// Subdomain represents a discovered subdomain.
type Subdomain struct {
    Name       string    `json:"name"`
    Source     string    `json:"source"`
    Discovered time.Time `json:"discovered"`
}

// DNSRecord represents DNS resolution information for a domain.
type DNSRecord struct {
    Name  string   `json:"name"`
    Type  string   `json:"type"`
    Value []string `json:"value"`
}

type HTTPService struct {
    URL          string            `json:"url"`
    StatusCode   int               `json:"status_code"`
    Title        string            `json:"title,omitempty"`
    Technologies []string          `json:"technologies,omitempty"`
    Headers      map[string]string `json:"headers,omitempty"`
}

type Port struct {
    Host     string `json:"host"`
    Port     int    `json:"port"`
    Protocol string `json:"protocol"`
    Service  string `json:"service,omitempty"`
}

type VulnFinding struct {
    ID         string    `json:"id"`
    Template   string    `json:"template"`
    Severity   string    `json:"severity"`
    Target     string    `json:"target"`
    Tags       []string  `json:"tags,omitempty"`
    Raw        string    `json:"raw,omitempty"`
    DetectedAt time.Time `json:"detected_at"`
}

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

// Enum4linuxResult contains the parsed output from enum4linux-ng for a given host.
type Enum4linuxResult struct {
    Host string                 `json:"host"`
    Data map[string]interface{} `json:"data"`
}

// NetBIOSName is a parsed NetBIOS name (from nbtstat/nbtscan).
type NetBIOSName struct {
    Name   string `json:"name"`
    Suffix string `json:"suffix"`
    Type   string `json:"type"` // UNIQUE/GROUP
}

// NetBIOSInfo aggregates NetBIOS information for a host.
type NetBIOSInfo struct {
    IP        string        `json:"ip"`
    Workgroup string        `json:"workgroup,omitempty"`
    Names     []NetBIOSName `json:"names"`
}

// NetexecResult holds the raw output of a netexec module invocation.
type NetexecResult struct {
    Host   string `json:"host"`
    Module string `json:"module"`
    Output string `json:"output"`
}