package privesc

import (
	"path/filepath"
	"strings"

	"github.com/MKlolbullen/rustygo/internal/model"
)

// AnalyzeHost runs OS-specific privesc checks and returns hints.
// It never does exploitation; it just looks at configuration.
func AnalyzeHost(p *model.HostProfile) []model.PrivescHint {
	if p == nil {
		return nil
	}
	switch strings.ToLower(p.OSFamily) {
	case "windows":
		return analyzeWindows(p)
	case "linux":
		return analyzeLinux(p)
	default:
		return nil
	}
}

// ----------------- Windows -----------------

func analyzeWindows(p *model.HostProfile) []model.PrivescHint {
	var hints []model.PrivescHint

	// 1) Interesting privileges
	privLower := make([]string, 0, len(p.Privileges))
	for _, pr := range p.Privileges {
		privLower = append(privLower, strings.ToLower(pr))
	}
	addWinPrivHint := func(match, title, desc string, sev string) {
		for _, pr := range privLower {
			if strings.Contains(pr, strings.ToLower(match)) {
				hints = append(hints, model.PrivescHint{
					Host:        p.Hostname,
					OSFamily:    p.OSFamily,
					Category:    "privileges",
					Severity:    sev,
					Title:       title,
					Description: desc,
					Evidence:    match,
					Reference:   "Search: SeImpersonatePrivilege privesc, Juicy Potato / PrintSpoofer style",
				})
				return
			}
		}
	}

	addWinPrivHint("SeImpersonatePrivilege",
		"Impersonation privilege present (SeImpersonatePrivilege)",
		"Account has SeImpersonatePrivilege. Token impersonation attacks may be possible depending on environment.",
		"high")

	addWinPrivHint("SeAssignPrimaryTokenPrivilege",
		"Assign primary token privilege (SeAssignPrimaryTokenPrivilege)",
		"Account can assign primary access tokens. May be usable to start processes under different security context.",
		"high")

	addWinPrivHint("SeBackupPrivilege",
		"Backup privilege present (SeBackupPrivilege)",
		"Backup files, including those with restricted ACLs, may allow access to sensitive data or registry hives.",
		"medium")

	addWinPrivHint("SeRestorePrivilege",
		"Restore privilege present (SeRestorePrivilege)",
		"Restore operations might allow overwriting sensitive files, potentially leading to privesc.",
		"medium")

	// 2) Services with suspicious binary paths
	for _, svc := range p.Services {
		bin := strings.TrimSpace(svc.BinaryPath)
		if bin == "" {
			continue
		}
		lower := strings.ToLower(bin)

		// Very naive heuristics: non-program files directories and spaces without quotes.
		if strings.Contains(lower, "c:\\temp") ||
			strings.Contains(lower, "c:\\users\\") ||
			strings.Contains(lower, "c:\\windows\\temp") {
			hints = append(hints, model.PrivescHint{
				Host:     p.Hostname,
				OSFamily: p.OSFamily,
				Category: "services",
				Severity: "high",
				Title:    "Service binary in user/temp directory",
				Description: "Service executable lives in a user or temp path. If the path is writable, this is a strong privesc candidate.",
				Evidence:    svc.Name + " -> " + svc.BinaryPath,
				Reference:   "Search: Windows service binary path privesc",
			})
		}

		// Unquoted service path with spaces.
		if !strings.HasPrefix(bin, "\"") && strings.Contains(bin, " ") {
			hints = append(hints, model.PrivescHint{
				Host:     p.Hostname,
				OSFamily: p.OSFamily,
				Category: "services",
				Severity: "medium",
				Title:    "Unquoted service path with spaces",
				Description: "Service binary path contains spaces and is unquoted. Depending on directory ACLs, this may be exploitable.",
				Evidence:    svc.Name + " -> " + svc.BinaryPath,
				Reference:   "Search: unquoted service path exploitation",
			})
		}

		// Service running as LocalSystem with writable path is a hot candidate,
		// but we can't prove 'writable' from here; just flag it if path looks non-standard.
		if strings.EqualFold(svc.RunAs, "localsystem") {
			if isNonStandardBinDir(lower) {
				hints = append(hints, model.PrivescHint{
					Host:     p.Hostname,
					OSFamily: p.OSFamily,
					Category: "services",
					Severity: "high",
					Title:    "Service running as LocalSystem from non-standard path",
					Description: "Service runs as LocalSystem and uses a non-standard binary path. If that path is writable, this is a strong privesc candidate.",
					Evidence:    svc.Name + " -> " + svc.BinaryPath,
				})
			}
		}
	}

	// 3) Local groups / membership
	for _, g := range p.LocalGroups {
		if strings.EqualFold(g.Name, "administrators") {
			for _, m := range g.Members {
				hints = append(hints, model.PrivescHint{
					Host:        p.Hostname,
					OSFamily:    p.OSFamily,
					Category:    "groups",
					Severity:    "high",
					Title:       "User in local Administrators group",
					Description: "Local Administrators membership can often be pivoted for full host compromise.",
					Evidence:    "Group: " + g.Name + " -> " + m,
				})
			}
		}
	}

	return hints
}

func isNonStandardBinDir(lowerPath string) bool {
	// Non-exhaustive, just tries to avoid flagging basic Program Files, System32 etc.
	standardPrefixes := []string{
		`c:\windows\system32`,
		`c:\windows\syswow64`,
		`c:\program files`,
		`c:\program files (x86)`,
	}
	for _, p := range standardPrefixes {
		if strings.HasPrefix(lowerPath, p) {
			return false
		}
	}
	return true
}

// ----------------- Linux -----------------

func analyzeLinux(p *model.HostProfile) []model.PrivescHint {
	var hints []model.PrivescHint

	// 1) Users with suspicious sudo hints (very simple: privilege name contains "sudo")
	for _, u := range p.LocalUsers {
		for _, h := range u.PasswordHints {
			if strings.Contains(strings.ToLower(h), "sudo") {
				hints = append(hints, model.PrivescHint{
					Host:        p.Hostname,
					OSFamily:    p.OSFamily,
					Category:    "sudo",
					Severity:    "medium",
					Title:       "User with potential sudo rights",
					Description: "User has a hint related to sudo; review sudoers configuration manually.",
					Evidence:    "User: " + u.Username + " hint: " + strings.Join(u.PasswordHints, ","),
				})
				break
			}
		}
	}

	// 2) Groups that often allow privesc: docker, lxd, libvirt, etc.
	for _, u := range p.LocalUsers {
		for _, g := range u.Groups {
			lg := strings.ToLower(g)
			if lg == "docker" || lg == "lxd" || strings.Contains(lg, "libvirt") {
				hints = append(hints, model.PrivescHint{
					Host:     p.Hostname,
					OSFamily: p.OSFamily,
					Category: "containers",
					Severity: "high",
					Title:    "User in container-related group",
					Description: "Membership in docker/lxd/libvirt-like groups may allow breaking out to root depending on configuration.",
					Evidence:    "User: " + u.Username + " group: " + g,
					Reference:   "Search: docker group privesc, lxd privesc",
				})
			}
		}
	}

	// 3) SUID/SGID-ish hints from processes / services paths
	// This is crude: if we see binaries in world-writable-ish locations, flag them.
	for _, svc := range p.Services {
		path := strings.ToLower(strings.TrimSpace(svc.BinaryPath))
		if path == "" {
			continue
		}
		if looksSuspiciousLinuxPath(path) {
			hints = append(hints, model.PrivescHint{
				Host:     p.Hostname,
				OSFamily: p.OSFamily,
				Category: "services",
				Severity: "medium",
				Title:    "Service binary in unusual path",
				Description: "Service uses a non-standard binary path. If combined with SUID/SGID or writable dirs, it could be a privesc vector.",
				Evidence:    svc.Name + " -> " + svc.BinaryPath,
				Reference:   "Search: linux service privesc, writable service path",
			})
		}
	}

	return hints
}

func looksSuspiciousLinuxPath(path string) bool {
	if strings.HasPrefix(path, "/usr/bin/") ||
		strings.HasPrefix(path, "/usr/sbin/") ||
		strings.HasPrefix(path, "/bin/") ||
		strings.HasPrefix(path, "/sbin/") {
		return false
	}
	// /tmp, /var/tmp, /dev/shm etc. are always spicy.
	suspiciousPrefixes := []string{
		"/tmp/",
		"/var/tmp/",
		"/dev/shm/",
		"/home/",
		"/mnt/",
		"/media/",
	}
	for _, p := range suspiciousPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	// If it's in the current directory (./something)
	if strings.HasPrefix(path, "./") {
		return true
	}
	// If there's no directory at all, treat as suspicious.
	if !strings.Contains(path, string(filepath.Separator)) {
		return true
	}
	return false
}
