package scripts

import (
    "context"
    "fmt"
    "os/exec"
    "path/filepath"
    "time"

    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/model"
)

// Runner knows how to list and run configured scripts.
type Runner struct {
    cfg *config.Config
}

func NewRunner(cfg *config.Config) *Runner {
    return &Runner{cfg: cfg}
}

// List returns script metadata for UI/CLI.
func (r *Runner) List() []model.Script {
    out := make([]model.Script, 0, len(r.cfg.Scripts))
    for _, sc := range r.cfg.Scripts {
        interp := sc.Interpreter
        if interp == "" {
            interp = "ruby"
        }
        out = append(out, model.Script{
            Name:        sc.Name,
            Path:        sc.Path,
            Interpreter: interp,
            Description: sc.Description,
            Tags:        sc.Tags,
        })
    }
    return out
}

// findConfig finds a script by name in config.
func (r *Runner) findConfig(name string) (*config.ScriptConfig, error) {
    for i := range r.cfg.Scripts {
        if r.cfg.Scripts[i].Name == name {
            return &r.cfg.Scripts[i], nil
        }
    }
    return nil, fmt.Errorf("script %q not found", name)
}

// Run executes the named script with optional extra args.
// It returns structured output and an exit code.
func (r *Runner) Run(ctx context.Context, name string, userArgs []string) (*model.ScriptRunResult, error) {
    sc, err := r.findConfig(name)
    if err != nil {
        return nil, err
    }

    interp := sc.Interpreter
    if interp == "" {
        interp = "ruby"
    }

    scriptPath := sc.Path
    // optional: normalize to absolute path
    if !filepath.IsAbs(scriptPath) {
        abs, err := filepath.Abs(scriptPath)
        if err == nil {
            scriptPath = abs
        }
    }

    args := []string{scriptPath}
    if len(sc.Args) > 0 {
        args = append(args, sc.Args...)
    }
    if len(userArgs) > 0 {
        args = append(args, userArgs...)
    }

    cmd := exec.CommandContext(ctx, interp, args...)
    // For now we don't set a working dir or env; you can customize later.

    started := time.Now().UTC()
    stdout, err := cmd.Output() // captures stdout, but not stderr; we want both
    // So instead, use CombinedOutput:
    // stdoutStderr, err := cmd.CombinedOutput()

    // Let's fix that:
}
