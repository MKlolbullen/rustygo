package ad

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/executil"
	"github.com/MKlolbullen/rustygo/internal/model"
)

// LDAPOptions configures an ldapsearch invocation.
type LDAPOptions struct {
	Host       string   // e.g. "ldap.example.com:389"
	BaseDN     string   // e.g. "DC=example,DC=com"
	Filter     string   // e.g. "(objectClass=user)"
	Attributes []string // e.g. ["cn","sAMAccountName"]

	BindDN   string // optional
	Password string // optional
	UseLDAPS bool   // if true, use ldaps://
}

// LDAPEngine wraps ldapsearch for directory enumeration.
type LDAPEngine struct {
	cfg *config.Config
}

func NewLDAPEngine(cfg *config.Config) *LDAPEngine {
	return &LDAPEngine{cfg: cfg}
}

// Search runs ldapsearch and parses LDIF output into a simplified result.
// Parsing is intentionally conservative and may not handle every edge case.
func (e *LDAPEngine) Search(ctx context.Context, opts LDAPOptions) (*model.LDAPResult, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if opts.BaseDN == "" {
		return nil, fmt.Errorf("base DN is required")
	}
	if opts.Filter == "" {
		opts.Filter = "(objectClass=*)"
	}

	bin := e.cfg.ToolPaths.Ldapsearch
	if bin == "" {
		bin = "ldapsearch"
	}

	scheme := "ldap"
	if opts.UseLDAPS {
		scheme = "ldaps"
	}

	args := []string{
		"-x",
		"-H", fmt.Sprintf("%s://%s", scheme, opts.Host),
		"-b", opts.BaseDN,
		opts.Filter,
	}
	if opts.BindDN != "" {
		args = append([]string{"-D", opts.BindDN, "-w", opts.Password}, args...)
	}
	if len(opts.Attributes) > 0 {
		args = append(args, opts.Attributes...)
	}

	res := executil.Run(ctx, bin, args...)
	if res.Err != nil {
		return nil, fmt.Errorf("ldapsearch error: %w\nstderr: %s", res.Err, string(res.Stderr))
	}

	raw := string(res.Stdout)
	entries := parseLDIF(raw)

	return &model.LDAPResult{
		Host:    opts.Host,
		BaseDN:  opts.BaseDN,
		Filter:  opts.Filter,
		Count:   len(entries),
		Entries: entries,
		Raw:     raw,
	}, nil
}

// parseLDIF performs a very simple LDIF parser suitable for common ldapsearch output.
func parseLDIF(raw string) []model.LDAPEntry {
	var entries []model.LDAPEntry
	scanner := bufio.NewScanner(strings.NewReader(raw))

	var currentDN string
	attrMap := map[string][]string{}
	flush := func() {
		if currentDN == "" && len(attrMap) == 0 {
			return
		}
		var attrs []model.LDAPAttribute
		for k, vs := range attrMap {
			attrs = append(attrs, model.LDAPAttribute{
				Name:   k,
				Values: append([]string(nil), vs...),
			})
		}
		entries = append(entries, model.LDAPEntry{
			DN:         currentDN,
			Attributes: attrs,
		})
		currentDN = ""
		attrMap = map[string][]string{}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "dn: ") {
			// start of new entry
			flush()
			currentDN = strings.TrimSpace(strings.TrimPrefix(line, "dn:"))
			continue
		}
		// simple "attr: value" lines
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// handle base64 or URLs very naively by just storing raw
		attrMap[key] = append(attrMap[key], val)
	}
	flush()

	return entries
}
