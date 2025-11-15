package windows

import (
    "context"
    "fmt"
    "strings"

    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/executil"
    "github.com/MKlolbullen/rustygo/internal/model"
)

// NetexecEngine wraps the netexec tool to perform advanced SMB/WinRM enumeration.
type NetexecEngine struct {
    cfg *config.Config
}

func NewNetexecEngine(cfg *config.Config) *NetexecEngine {
    return &NetexecEngine{cfg: cfg}
}

func (e *NetexecEngine) Run(ctx context.Context, module string, target string, flags []string) (*model.NetexecResult, error) {
    if module == "" {
        return nil, fmt.Errorf("module is required")
    }
    if target == "" {
        return nil, fmt.Errorf("target is required")
    }
    bin := e.cfg.ToolPaths.Netexec
    if bin == "" {
        bin = "netexec"
    }
    args := []string{module, target}
    args = append(args, flags...)

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, res.Err
    }
    out := string(res.Stdout)
    if len(res.Stderr) > 0 {
        out = strings.TrimRight(out, "\n") + "\n" + string(res.Stderr)
    }
    return &model.NetexecResult{Host: target, Module: module, Output: out}, nil
}
