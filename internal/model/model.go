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

// HTTPService represents an HTTP(S) service discovered on a host.
type HTTPService struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
}

// Port represents a network port discovered during scanning.
type Port struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
}

// VulnFinding represents a vulnerability finding (e.g. from nuclei).
type VulnFinding struct {
	ID         string    `json:"id"`
	Template   string    `json:"template"`
	Severity   string    `json:"severity"`
	Target     string    `json:"target"`
	Tags       []string  `json:"tags,omitempty"`
	Raw        string    `json:"raw,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
}

// ReconResult bundles the main recon phases for a domain.
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
// HTTPBruteResult represents a single result from ffuf/feroxbuster discovery.
type HTTPBruteResult struct {
    Tool       string   `json:"tool"`
    URL        string   `json:"url"`
    StatusCode int      `json:"status_code"`
    Length     int      `json:"length,omitempty"`
    Words      int      `json:"words,omitempty"`
    Lines      int      `json:"lines,omitempty"`
    Method     string   `json:"method,omitempty"`
    Tags       []string `json:"tags,omitempty"`
}

// WebTechInfo aggregates technology fingerprinting for a URL.
type WebTechInfo struct {
    URL          string                 `json:"url"`
    Technologies []string               `json:"technologies"`
    Raw          map[string]interface{} `json:"raw,omitempty"`
}

// FaviconInfo describes a favicon hash and optional saved path.
type FaviconInfo struct {
    URL      string `json:"url"`
    Hash     string `json:"hash"`
    IconPath string `json:"icon_path,omitempty"`
}

// CSPInfo represents a parsed Content-Security-Policy.
type CSPInfo struct {
    URL        string              `json:"url"`
    Directives map[string][]string `json:"directives,omitempty"`
    Raw        string              `json:"raw,omitempty"`
}

// NetworkExposure describes output from tools like nextnet.
type NetworkExposure struct {
    Target string `json:"target"`
    Output string `json:"output"`
}

// Enum4linuxResult contains parsed output from enum4linux-ng.
type Enum4linuxResult struct {
	Host string                 `json:"host"`
	Data map[string]interface{} `json:"data"`
}

// NetBIOSName is a parsed NetBIOS name.
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

// LDAPAttribute is a single attribute with multiple values.
type LDAPAttribute struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// LDAPEntry represents one LDAP entry from ldapsearch output.
type LDAPEntry struct {
	DN         string          `json:"dn"`
	Attributes []LDAPAttribute `json:"attributes"`
}

// LDAPResult encapsulates an ldapsearch query result.
type LDAPResult struct {
	Host    string       `json:"host"`
	BaseDN  string       `json:"base_dn"`
	Filter  string       `json:"filter"`
	Count   int          `json:"count"`
	Entries []LDAPEntry  `json:"entries"`
	Raw     string       `json:"raw,omitempty"`
}

// SMBShare describes a discovered SMB share.
type SMBShare struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
	Read    bool   `json:"read"`
	Write   bool   `json:"write"`
}

// SMBEnumResult is the result of SMB share enumeration.
type SMBEnumResult struct {
	Host      string     `json:"host"`
	Tool      string     `json:"tool"`
	Shares    []SMBShare `json:"shares"`
	RawOutput string     `json:"raw_output,omitempty"`
}

// BloodHoundSummary provides a lightweight summary of a BloodHound JSON export.
type BloodHoundSummary struct {
	NodeCount int            `json:"node_count"`
	EdgeCount int            `json:"edge_count"`
	NodeTypes map[string]int `json:"node_types"`
}

// MetasploitCommandResult represents the result of a msfconsole command run.
type MetasploitCommandResult struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`
}
