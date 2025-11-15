package model

// HostProfile is a unified view of a single host, regardless of how the data
// was collected (local agent, C2, manual export). It tries to be generic and
// AD/C2-agnostic.
type HostProfile struct {
	Hostname       string           `json:"hostname"`
	OSFamily       string           `json:"os_family"`        // windows, linux, macos, other
	OSVersion      string           `json:"os_version"`
	Architecture   string           `json:"architecture"`     // amd64, arm64, etc
	Domain         string           `json:"domain,omitempty"` // AD or local domain
	IsDomainJoined bool             `json:"is_domain_joined"`
	LoggedOnUsers  []string         `json:"logged_on_users,omitempty"`

	LocalUsers   []LocalUser        `json:"local_users,omitempty"`
	LocalGroups  []LocalGroup       `json:"local_groups,omitempty"`
	Processes    []Process          `json:"processes,omitempty"`
	Services     []Service          `json:"services,omitempty"`  // esp. Windows services / daemons
	Network      NetworkInfo        `json:"network"`
	AVProducts   []AVProduct        `json:"av_products,omitempty"`
	Privileges   []string           `json:"privileges,omitempty"` // e.g. SeImpersonatePrivilege, sudo etc.
	Notes        string             `json:"notes,omitempty"`
}

// LocalUser represents a local account on the host.
type LocalUser struct {
	Username      string   `json:"username"`
	UID           string   `json:"uid,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	HomeDir       string   `json:"home_dir,omitempty"`
	Shell         string   `json:"shell,omitempty"` // mainly *nix
	IsAdmin       bool     `json:"is_admin"`
	IsDisabled    bool     `json:"is_disabled"`
	PasswordHints []string `json:"password_hints,omitempty"` // e.g. "no_password_set", "password_never_expires"
}

// LocalGroup represents a local group and its members.
type LocalGroup struct {
	Name    string   `json:"name"`
	Members []string `json:"members,omitempty"`
}

// Process represents a running process.
type Process struct {
	PID        int      `json:"pid"`
	ParentPID  int      `json:"ppid"`
	Name       string   `json:"name"`
	Path       string   `json:"path,omitempty"`
	User       string   `json:"user,omitempty"`
	Arguments  string   `json:"arguments,omitempty"`
	ListenPorts []int   `json:"listen_ports,omitempty"`
	Integrity  string   `json:"integrity,omitempty"` // for Windows: Low/Medium/High/System
}

// Service represents a system service / daemon.
type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	StartMode   string `json:"start_mode,omitempty"`  // auto, manual, disabled
	Status      string `json:"status,omitempty"`      // running, stopped
	RunAs       string `json:"run_as,omitempty"`      // LocalSystem, root, DOMAIN\user
	CanInteract bool   `json:"can_interact,omitempty"` // Windows "Interact with desktop"
}

// NetworkInfo represents host network configuration.
type NetworkInfo struct {
	Interfaces  []NetworkInterface  `json:"interfaces,omitempty"`
	Connections []NetworkConnection `json:"connections,omitempty"`
}

// NetworkInterface represents a single NIC.
type NetworkInterface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"` // IPs/CIDRs
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
}

// NetworkConnection represents a local connection/port.
type NetworkConnection struct {
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Protocol   string `json:"protocol"` // tcp, udp
	State      string `json:"state,omitempty"`
	ProcessPID int    `json:"process_pid,omitempty"`
}

// AVProduct represents a detected AV/EDR/endpoint security product.
type AVProduct struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"` // AV, EDR, EPP, etc.
}
