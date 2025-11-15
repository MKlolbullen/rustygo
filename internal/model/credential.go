package model

import "time"

// CredentialType describes what kind of thing this is.
type CredentialType string

const (
	CredTypePassword  CredentialType = "password"
	CredTypeNTLMHash  CredentialType = "ntlm_hash"
	CredTypeKerbTicket CredentialType = "kerberos_ticket"
	CredTypeAPIKey    CredentialType = "api_key"
)

// Credential represents a single captured credential for an account.
type Credential struct {
	ID         string         `json:"id"`
	Engagement string         `json:"engagement"`
	Account    string         `json:"account"`     // e.g. user@DOMAIN, svc_sql@CORP.LOCAL
	Type       CredentialType `json:"type"`
	Secret     string         `json:"secret"`      // hash / ticket / redacted value
	SourceTool string         `json:"source_tool"` // "external", "import", "manual"
	SourceNote string         `json:"source_note,omitempty"`

	Host        string    `json:"host,omitempty"`       // where we grabbed it
	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`

	// Optional tags, e.g. ["asrep", "kerberoast", "spray"]
	Tags []string `json:"tags,omitempty"`
}

// Session represents "user X has/had a session on host Y".
type Session struct {
	ID         string    `json:"id"`
	Engagement string    `json:"engagement"`
	User       string    `json:"user"`  // user@DOMAIN
	Host       string    `json:"host"`  // hostname or IP
	SourceTool string    `json:"source_tool"`
	SourceNote string    `json:"source_note,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}
