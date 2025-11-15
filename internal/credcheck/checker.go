type CredCheckResult struct {
    Host      string `json:"host"`
    Account   string `json:"account"`
    Success   bool   `json:"success"`
    Mechanism string `json:"mechanism"` // "smb", "rdp", etc.
}
