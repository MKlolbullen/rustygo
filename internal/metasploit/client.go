package metasploit

import (
	"context"
	"fmt"
	"strings"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/executil"
	"github.com/MKlolbullen/rustygo/internal/model"
)

// Client is a thin wrapper around msfconsole for running scripted commands.
// This is intentionally minimal and leaves module selection to the operator.
type Client struct {
	bin string
}

func NewClient(cfg *config.Config) *Client {
	bin := cfg.ToolPaths.Msfconsole
	if bin == "" {
		bin = "msfconsole"
	}
	return &Client{bin: bin}
}

// RunScript executes a sequence of Metasploit console commands as a single
// "-x" script, then exits. Example script value:
// "use auxiliary/scanner/http/title; set RHOSTS 10.0.0.0/24; run"
func (c *Client) RunScript(ctx context.Context, script string) (*model.MetasploitCommandResult, error) {
	script = strings.TrimSpace(script)
	if script == "" {
		return nil, fmt.Errorf("script is empty")
	}
	// Ensure we exit msfconsole at the end
	if !strings.Contains(script, "exit") {
		script = script + "; exit"
	}
	args := []string{"-q", "-x", script}
	res := executil.Run(ctx, c.bin, args...)
	if res.Err != nil {
		return &model.MetasploitCommandResult{
			Success: false,
			Output:  string(res.Stdout) + "\n" + string(res.Stderr),
		}, fmt.Errorf("msfconsole error: %w", res.Err)
	}
	return &model.MetasploitCommandResult{
		Success: true,
		Output:  string(res.Stdout),
	}, nil
}
