package windows

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/executil"
	"github.com/MKlolbullen/rustygo/internal/model"
)

// SMBEnumOptions configures SMB share enumeration.
type SMBEnumOptions struct {
	Host     string
	Username string
	Password string
	Domain   string
	Tool     string // "smbclient" or "smbmap" (default smbclient)
}

// SMBEnumerator wraps smbclient / smbmap for share enumeration.
type SMBEnumerator struct {
	cfg *config.Config
}

func NewSMBEnumerator(cfg *config.Config) *SMBEnumerator {
	return &SMBEnumerator{cfg: cfg}
}

func (e *SMBEnumerator) EnumShares(ctx context.Context, opts SMBEnumOptions) (*model.SMBEnumResult, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	tool := strings.ToLower(opts.Tool)
	if tool == "" {
		tool = "smbclient"
	}
	switch tool {
	case "smbmap":
		return e.enumSmbmap(ctx, opts)
	default:
		return e.enumSmbclient(ctx, opts)
	}
}

func (e *SMBEnumerator) enumSmbclient(ctx context.Context, opts SMBEnumOptions) (*model.SMBEnumResult, error) {
	bin := e.cfg.ToolPaths.Smbclient
	if bin == "" {
		bin = "smbclient"
	}

	var args []string
	if opts.Username == "" {
		// anonymous
		args = append(args, "-N", "-L", opts.Host)
	} else {
		cred := opts.Username
		if opts.Password != "" {
			cred = cred + "%" + opts.Password
		}
		if opts.Domain != "" {
			cred = opts.Domain + `\` + cred
		}
		args = append(args, "-L", opts.Host, "-U", cred)
	}

	res := executil.Run(ctx, bin, args...)
	if res.Err != nil {
		return nil, fmt.Errorf("smbclient error: %w\nstderr: %s", res.Err, string(res.Stderr))
	}

	raw := string(res.Stdout)
	shares := parseSmbclientShares(raw)

	return &model.SMBEnumResult{
		Host:      opts.Host,
		Tool:      "smbclient",
		Shares:    shares,
		RawOutput: raw,
	}, nil
}

// parseSmbclientShares parses the classic "Sharename / Type / Comment" output.
func parseSmbclientShares(raw string) []model.SMBShare {
	var shares []model.SMBShare
	scanner := bufio.NewScanner(strings.NewReader(raw))
	inTable := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Sharename") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Server") || strings.HasPrefix(line, "Workgroup") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], "IPC$") {
			// still include IPC$; some folks like it
		}
		name := fields[0]
		comment := ""
		if len(fields) > 2 {
			comment = strings.Join(fields[2:], " ")
		}
		shares = append(shares, model.SMBShare{
			Name:    name,
			Comment: comment,
			Read:    false,
			Write:   false,
		})
	}
	return shares
}

func (e *SMBEnumerator) enumSmbmap(ctx context.Context, opts SMBEnumOptions) (*model.SMBEnumResult, error) {
	bin := e.cfg.ToolPaths.Smbmap
	if bin == "" {
		bin = "smbmap"
	}

	args := []string{"-H", opts.Host}
	if opts.Username != "" {
		args = append(args, "-u", opts.Username)
	}
	if opts.Password != "" {
		args = append(args, "-p", opts.Password)
	}
	if opts.Domain != "" {
		args = append(args, "-d", opts.Domain)
	}

	res := executil.Run(ctx, bin, args...)
	if res.Err != nil {
		return nil, fmt.Errorf("smbmap error: %w\nstderr: %s", res.Err, string(res.Stderr))
	}

	// smbmap output parsing can get gnarly; for now we just keep raw output and
	// let the operator interpret it, while still returning an empty share list.
	raw := string(res.Stdout)

	return &model.SMBEnumResult{
		Host:      opts.Host,
		Tool:      "smbmap",
		Shares:    nil,
		RawOutput: raw,
	}, nil
}
