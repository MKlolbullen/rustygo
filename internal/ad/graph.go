package ad

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MKlolbullen/rustygo/internal/model"
)

// ParseBloodHoundGraph tries to parse a BloodHound-style JSON graph export
// into a simplified ADGraph. It makes some assumptions about the schema,
// but fails gracefully if fields are missing.
func ParseBloodHoundGraph(data []byte) (*model.ADGraph, error) {
	// Very generic shape: { "nodes": [ { "id": ..., "label": ..., "properties": {...} } ], "edges": [...] }
	var raw struct {
		Nodes []struct {
			ID         interface{}            `json:"id"`
			Label      string                 `json:"label"`
			Properties map[string]interface{} `json:"properties"`
		} `json:"nodes"`
		Edges []struct {
			Source interface{} `json:"source"`
			Target interface{} `json:"target"`
			Label  string      `json:"label"`
		} `json:"edges"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse bloodhound json: %w", err)
	}

	graph := &model.ADGraph{
		Nodes: make([]model.ADGraphNode, 0, len(raw.Nodes)),
		Edges: make([]model.ADGraphEdge, 0, len(raw.Edges)),
	}

	// We keep an index from "raw index" (0..N-1) to node ID for edges that
	// refer by index. If ID is not numeric, we use string version of ID.
	idByIndex := make([]string, len(raw.Nodes))

	for idx, n := range raw.Nodes {
		id := fmt.Sprintf("%v", n.ID)
		idByIndex[idx] = id

		name := ""
		if v, ok := n.Properties["name"]; ok {
			name = fmt.Sprintf("%v", v)
		} else if v, ok := n.Properties["Name"]; ok {
			name = fmt.Sprintf("%v", v)
		}

		high := isHighValueNode(n.Label, name, n.Properties)
		state := ""
		if high {
			state = "high_value"
		}

		graph.Nodes = append(graph.Nodes, model.ADGraphNode{
			ID:        id,
			Label:     n.Label,
			Name:      name,
			HighValue: high,
			State:     state,
		})
	}

	for _, e := range raw.Edges {
		srcID := toNodeID(e.Source, idByIndex)
		dstID := toNodeID(e.Target, idByIndex)
		if srcID == "" || dstID == "" {
			continue
		}
		graph.Edges = append(graph.Edges, model.ADGraphEdge{
			Source: srcID,
			Target: dstID,
			Kind:   e.Label,
		})
	}

	return graph, nil
}

func toNodeID(v interface{}, idByIndex []string) string {
	switch t := v.(type) {
	case float64:
		i := int(t)
		if i >= 0 && i < len(idByIndex) {
			return idByIndex[i]
		}
		return fmt.Sprintf("%d", i)
	case int:
		if t >= 0 && t < len(idByIndex) {
			return idByIndex[t]
		}
		return fmt.Sprintf("%d", t)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func isHighValueNode(label, name string, props map[string]interface{}) bool {
	// If BloodHound explicitly flags highvalue=true, trust that.
	if v, ok := props["highvalue"]; ok {
		switch vv := v.(type) {
		case bool:
			return vv
		case string:
			return strings.EqualFold(vv, "true")
		}
	}
	lowerName := strings.ToLower(name)
	lowerLabel := strings.ToLower(label)

	// Heuristics:
	// - Names containing common Tier 0 patterns
	highPatterns := []string{
		"domain admins",
		"enterprise admins",
		"schema admins",
		"administrators@",
		"krbtgt@",
	}
	for _, p := range highPatterns {
		if strings.Contains(lowerName, p) {
			return true
		}
	}

	// Users with clearly admin-like names.
	if lowerLabel == "user" {
		if strings.Contains(lowerName, "admin@") || strings.Contains(lowerName, ".adm@") {
			return true
		}
	}

	return false
}
