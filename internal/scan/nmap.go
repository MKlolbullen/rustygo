package scan

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// GraphNode is a simple node representation compatible with D3 force layouts.
type GraphNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"`            // "host", "service", etc.
	Label string `json:"label,omitempty"` // nice human label
}

// GraphLink connects two nodes by ID.
type GraphLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// GraphData is the full node-link graph returned to the frontend.
type GraphData struct {
	Nodes []GraphNode `json:"nodes"`
	Links []GraphLink `json:"links"`
}

// NmapScanner wraps the external nmap binary.
type NmapScanner struct {
	Binary string
}

// NewNmapScanner creates a scanner; if bin is empty, "nmap" is used.
func NewNmapScanner(bin string) *NmapScanner {
	if bin == "" {
		bin = "nmap"
	}
	return &NmapScanner{Binary: bin}
}

// RunGraph runs nmap for a single target and returns a node-link graph of hosts/services.
func (s *NmapScanner) RunGraph(ctx context.Context, target string, extraArgs []string) (*GraphData, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("target is required")
	}

	// Base args. We leave "how aggressive" to the caller via extraArgs.
	args := append([]string{}, extraArgs...)
	// Ensure XML output to stdout so we can parse it.
	if !hasXMLOutput(args) {
		args = append(args, "-oX", "-")
	}
	args = append(args, target)

	cmd := exec.CommandContext(ctx, s.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nmap error: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	graph, err := parseNmapToGraph(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	return graph, nil
}

func hasXMLOutput(args []string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "-oX" {
			return true
		}
		if strings.HasPrefix(args[i], "-oX") {
			return true
		}
	}
	return false
}

// ---------------- XML parsing ----------------

// We only model the XML bits we care about.

type nmapRun struct {
	XMLName xml.Name  `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string     `xml:"protocol,attr"`
	PortID   int        `xml:"portid,attr"`
	State    nmapState  `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// parseNmapToGraph turns XML into a simple host->service graph.
func parseNmapToGraph(data []byte) (*GraphData, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	graph := &GraphData{
		Nodes: []GraphNode{},
		Links: []GraphLink{},
	}

	nodeIndex := map[string]struct{}{}

	addNode := func(n GraphNode) {
		if _, ok := nodeIndex[n.ID]; ok {
			return
		}
		nodeIndex[n.ID] = struct{}{}
		graph.Nodes = append(graph.Nodes, n)
	}

	addLink := func(src, dst string) {
		graph.Links = append(graph.Links, GraphLink{Source: src, Target: dst})
	}

	for _, h := range run.Hosts {
		hostID, hostLabel := hostIdentity(h)
		if hostID == "" {
			continue
		}
		addNode(GraphNode{
			ID:    hostID,
			Type:  "host",
			Label: hostLabel,
		})

		for _, p := range h.Ports.Ports {
			if strings.ToLower(p.State.State) != "open" {
				continue
			}
			svcID := fmt.Sprintf("%s:%d/%s", hostID, p.PortID, p.Protocol)
			label := fmt.Sprintf("%d/%s", p.PortID, p.Protocol)
			if p.Service.Name != "" {
				label += " (" + p.Service.Name
				if p.Service.Product != "" {
					label += " " + p.Service.Product
				}
				if p.Service.Version != "" {
					label += " " + p.Service.Version
				}
				label += ")"
			}
			addNode(GraphNode{
				ID:    svcID,
				Type:  "service",
				Label: label,
			})
			addLink(hostID, svcID)
		}
	}

	return graph, nil
}

func hostIdentity(h nmapHost) (id string, label string) {
	var ip, hostname string
	for _, a := range h.Addresses {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			ip = a.Addr
			break
		}
	}
	if len(h.Hostnames.Hostnames) > 0 {
		hostname = h.Hostnames.Hostnames[0].Name
	}
	switch {
	case ip != "" && hostname != "":
		return ip, hostname + " (" + ip + ")"
	case ip != "":
		return ip, ip
	case hostname != "":
		return hostname, hostname
	default:
		return "", ""
	}
}

// Helper to parse a portID string when needed.
func parsePortID(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// WithTimeout wraps context.WithTimeout and uses it for default scan contexts.
// You can ignore this helper and use your own ctx in the caller.
func WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}