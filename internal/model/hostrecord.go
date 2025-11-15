package model

import "time"

// HostRecord ties a HostProfile + privesc hints to an "engagement" scope.
// Engagement can be anything: external domain, AD forest name, etc.
type HostRecord struct {
	Engagement  string         `json:"engagement"`
	Profile     *HostProfile   `json:"profile"`
	Hints       []PrivescHint  `json:"hints"`
	Owned       bool           `json:"owned"`
	OwnerNote   string         `json:"owner_note,omitempty"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastUpdated time.Time      `json:"last_updated"`
}
