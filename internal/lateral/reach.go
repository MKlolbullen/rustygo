type Reachability struct {
    FromHost string   `json:"from_host"`
    ToHost   string   `json:"to_host"`
    Ports    []int    `json:"ports"`
    Proto    string   `json:"proto"` // "tcp"
}
