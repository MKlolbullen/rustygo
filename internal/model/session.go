package model

import "time"

// CredentialType describes what kind of credential this is.
type CredentialType string

const (
	CredTypePassword   CredentialType = "password"
	CredTypeNTLMHash   CredentialType = "ntlm_hash"
	CredTypeKerbTicket CredentialType = "kerberos_ticket"
	CredTypeAPIKey     CredentialType = "api_key"
)

// Credential represents a single captured credential for an account.
// This is intentionally generic so it can represent output from many tools.
type Credential struct {
	ID         string         `json:"id"`
	Engagement string         `json:"engagement"`           // scope / tenant / forest / customer
	Account    string         `json:"account"`              // user@DOMAIN, machine$, svc_x@DOMAIN
	Type       CredentialType `json:"type"`                 // password / ntlm_hash / kerberos_ticket / api_key
	Secret     string         `json:"secret"`               // hash / ticket / secret (consider redacting in UI if needed)
	SourceTool string         `json:"source_tool"`          // e.g. "import", "manual", "external"
	SourceNote string         `json:"source_note,omitempty"`

	Host        string    `json:"host,omitempty"`        // where we grabbed it (hostname / IP)
	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`

	// Optional tags such as ["kerberoast","asrep","spray"].
	Tags []string `json:"tags,omitempty"`
}
