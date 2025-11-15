package model

// PrivescHint is a *hint*, not an exploit. It points to potential issues that
// an operator can manually investigate.
type PrivescHint struct {
	Host        string `json:"host"`
	OSFamily    string `json:"os_family"`
	Category    string `json:"category"`    // services, sudo, perms, tokens, creds, containers, etc.
	Severity    string `json:"severity"`    // info, low, medium, high, critical
	Title       string `json:"title"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"` // short blob of output / file path / config snippet
	Reference   string `json:"reference,omitempty"` // optional: URL or “CWE-xxx”
}
