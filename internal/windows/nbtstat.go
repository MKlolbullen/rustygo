package windows

import (
    "bufio"
    "context"
    "fmt"
    "path/filepath"
    "regexp"
    "strings"

    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/executil"
    "github.com/MKlolbullen/rustygo/internal/model"
)

// NetBIOSScanner performs NetBIOS name lookups using either nbtstat (Windows)
// or nbtscan (Unix).
type NetBIOSScanner struct {
    cfg *config.Config
}

func NewNetBIOSScanner(cfg *config.Config) *NetBIOSScanner {
    return &NetBIOSScanner{cfg: cfg}
}

func (s *NetBIOSScanner) Scan(ctx context.Context, ip string) (*model.NetBIOSInfo, error) {
    if ip == "" {
        return nil, fmt.Errorf("IP is required")
    }

    bin := s.cfg.ToolPaths.Nbtstat
    var args []string
    if bin == "" {
        bin = "nbtstat"
        args = []string{"-A", ip}
    } else {
        base := strings.ToLower(filepath.Base(bin))
        if strings.Contains(base, "nbtscan") {
            args = []string{"-v", ip}
        } else {
            args = []string{"-A", ip}
        }
    }

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, res.Err
    }
    output := string(res.Stdout)

    if strings.Contains(strings.ToLower(bin), "nbtscan") {
        return parseNbtscanOutput(ip, output), nil
    }
    return parseNbtstatOutput(ip, output), nil
}

func parseNbtstatOutput(ip, output string) *model.NetBIOSInfo {
    scanner := bufio.NewScanner(strings.NewReader(output))
    re := regexp.MustCompile(`(?i)^\s*([^\s<]+)\s+<([0-9A-F]{2})>\s+(UNIQUE|GROUP)\s+.*`)
    var names []model.NetBIOSName
    workgroup := ""

    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }
        if m := re.FindStringSubmatch(line); m != nil {
            names = append(names, model.NetBIOSName{
                Name:   m[1],
                Suffix: strings.ToUpper(m[2]),
                Type:   strings.ToUpper(m[3]),
            })
            continue
        }
        lower := strings.ToLower(line)
        if strings.HasPrefix(lower, "workgroup") {
            parts := strings.Fields(line)
            if len(parts) > 0 {
                workgroup = parts[0]
            }
        }
    }
    return &model.NetBIOSInfo{IP: ip, Workgroup: workgroup, Names: names}
}

func parseNbtscanOutput(ip, output string) *model.NetBIOSInfo {
    info := &model.NetBIOSInfo{IP: ip}
    scanner := bufio.NewScanner(strings.NewReader(output))
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "--") {
            continue
        }
        fields := strings.Fields(line)
        if len(fields) < 2 {
            continue
        }
        if fields[0] != ip {
            continue
        }
        nameWithSuffix := fields[1]
        if idx := strings.Index(nameWithSuffix, "<"); idx != -1 {
            name := nameWithSuffix[:idx]
            suffix := nameWithSuffix[idx+1 : idx+3]
            info.Names = append(info.Names, model.NetBIOSName{
                Name:   name,
                Suffix: strings.ToUpper(suffix),
                Type:   "GROUP",
            })
            info.Workgroup = name
        }
        break
    }
    return info
}
