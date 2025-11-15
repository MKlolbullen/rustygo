package model

// ADGraphNode is a simplified view of a BloodHound node.
type ADGraphNode struct {
	ID        string `json:"id"`
	Label     string `json:"label"`      // e.g. "User", "Computer", "Group"
	Name      string `json:"name"`       // "USER@DOMAIN.LOCAL"
	HighValue bool   `json:"high_value"` // Tier 0 / crown jewel heuristic
}

// ADGraphEdge is a simplified relationship between nodes.
type ADGraphEdge struct {
	Source string `json:"source"` // ID of source node
	Target string `json:"target"` // ID of target node
	Kind   string `json:"kind"`   // e.g. "MemberOf", "AdminTo", "HasSession", ...
}

// ADGraph is a simplified version of a BloodHound graph, suitable for UI.
type ADGraph struct {
	Nodes []ADGraphNode `json:"nodes"`
	Edges []ADGraphEdge `json:"edges"`
}
