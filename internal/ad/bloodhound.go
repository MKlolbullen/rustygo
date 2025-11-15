package ad

import (
	"encoding/json"
	"fmt"

	"github.com/MKlolbullen/rustygo/internal/model"
)

// BloodHoundEngine provides helpers for summarizing BloodHound JSON.
type BloodHoundEngine struct{}

func NewBloodHoundEngine() *BloodHoundEngine {
	return &BloodHoundEngine{}
}

// SummarizeJSONBytes attempts to parse a BloodHound-style JSON graph export and
// returns counts of nodes, edges, and node types. It is intentionally generic.
func (b *BloodHoundEngine) SummarizeJSONBytes(data []byte) (*model.BloodHoundSummary, error) {
	// We try to detect a shape like:
	// { "nodes": [ { "label": "User", ... }, ... ], "edges": [ ... ] }
	var raw struct {
		Nodes []struct {
			Label string `json:"label"`
		} `json:"nodes"`
		Edges []json.RawMessage `json:"edges"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse bloodhound json: %w", err)
	}

	nodeTypes := make(map[string]int)
	for _, n := range raw.Nodes {
		l := n.Label
		if l == "" {
			l = "unknown"
		}
		nodeTypes[l]++
	}

	return &model.BloodHoundSummary{
		NodeCount: len(raw.Nodes),
		EdgeCount: len(raw.Edges),
		NodeTypes: nodeTypes,
	}, nil
}
