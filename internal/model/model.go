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

// HTTPService describes an HTTP endpoint discovered during recon.
type HTTPService struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
}

// Port describes a network port discovered during scanning.
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

// ReconResult aggregates the full recon output for a given domain.
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
	Type   string `json:"type"` // UNIQUE or GROUP
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

// WebScreenshot represents a screenshot plus some metadata for a URL.
type WebScreenshot struct {
	URL            string `json:"url"`
	ScreenshotPath string `json:"screenshot_path"`
	Title          string `json:"title,omitempty"`
	FaviconHash    string `json:"favicon_hash,omitempty"`
}

type CredentialType string

const (
	CredTypePassword CredentialType = "password"
	CredTypeHash     CredentialType = "hash"
	CredTypeTicket   CredentialType = "ticket"
	CredTypeAPIKey   CredentialType = "api_key"
)

// Credential represents a single credential item discovered/imported.
type Credential struct {
	ID        string         `json:"id"`
	Type      CredentialType `json:"type"`
	Username  string         `json:"username"`
	Domain    string         `json:"domain,omitempty"`
	Secret    string         `json:"secret,omitempty"` // consider masking/redaction in UI
	Source    string         `json:"source,omitempty"`
	Host      string         `json:"host,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	Tags      []string       `json:"tags,omitempty"`
}

// CredCheckResult represents a credential validity check against a host.
type CredCheckResult struct {
	CredentialID string `json:"credential_id"`
	Host         string `json:"host"`
	Success      bool   `json:"success"`
	Mechanism    string `json:"mechanism"`
	Error        string `json:"error,omitempty"`
}

// HostProfile represents situational awareness on a compromised host.
type HostProfile struct {
	Name           string    `json:"name"`
	OS             string    `json:"os"`
	OSVersion      string    `json:"os_version,omitempty"`
	Domain         string    `json:"domain,omitempty"`
	IPs            []string  `json:"ips,omitempty"`
	LocalAdmins    []string  `json:"local_admins,omitempty"`
	AVProducts     []string  `json:"av_products,omitempty"`
	LoggedOnUsers  []string  `json:"logged_on_users,omitempty"`
	IsDomainJoined bool      `json:"is_domain_joined"`
	Tags           []string  `json:"tags,omitempty"`
	LastSeen       time.Time `json:"last_seen"`
}

type PrivescHintSeverity string

const (
	PrivescLow      PrivescHintSeverity = "low"
	PrivescMedium   PrivescHintSeverity = "medium"
	PrivescHigh     PrivescHintSeverity = "high"
	PrivescCritical PrivescHintSeverity = "critical"
)

// PrivescHint describes a potential privilege escalation opportunity (enumeration only).
type PrivescHint struct {
	Host        string              `json:"host"`
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Severity    PrivescHintSeverity `json:"severity"`
	Category    string              `json:"category,omitempty"`
	Description string              `json:"description,omitempty"`
	Evidence    string              `json:"evidence,omitempty"`
	References  []string            `json:"references,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
}

// Script describes a runnable script exposed via CLI/GUI.
type Script struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Interpreter string   `json:"interpreter,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// ScriptRunRequest is what the GUI/CLI send to the HTTP API when running a script.
type ScriptRunRequest struct {
	Name string   `json:"name"`
	Args []string `json:"args,omitempty"`
}

// ScriptRunResult is the structured output of a script execution.
type ScriptRunResult struct {
	Name       string    `json:"name"`
	ExitCode   int       `json:"exit_code"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// IPEnrichment aggregates OSINT data about an IP address from multiple providers.
type IPEnrichment struct {
	IP string `json:"ip"`

	Shodan     map[string]interface{} `json:"shodan,omitempty"`
	Censys     map[string]interface{} `json:"censys,omitempty"`
	BinaryEdge map[string]interface{} `json:"binaryedge,omitempty"`
	IPInfo     map[string]interface{} `json:"ipinfo,omitempty"`
	VirusTotal map[string]interface{} `json:"virustotal,omitempty"`
	Netlas     map[string]interface{} `json:"netlas,omitempty"`

	// Per-provider errors (e.g. quota, network, auth)
	Errors map[string]string `json:"errors,omitempty"`
}

// DomainEnrichment aggregates OSINT data about a domain.
type DomainEnrichment struct {
	Domain     string                 `json:"domain"`
	URLScan    map[string]interface{} `json:"urlscan,omitempty"`    // e.g. submission UUID
	VirusTotal map[string]interface{} `json:"virustotal,omitempty"` // VT domain report
	Netlas     map[string]interface{} `json:"netlas,omitempty"`
	DNSTwister map[string]interface{} `json:"dnstwister,omitempty"`

	Errors map[string]string `json:"errors,omitempty"`
}
