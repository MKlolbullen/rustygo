package windows

import (
    "context"
    "encoding/json"
    "fmt"
    "os"

    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/executil"
    "github.com/MKlolbullen/rustygo/internal/model"
)

// Enum4LinuxEngine wraps the enum4linux-ng tool to enumerate Windows/Samba
// environments. It exports the results as JSON and returns them as a map.
type Enum4LinuxEngine struct {
    cfg *config.Config
}

// NewEnum4LinuxEngine constructs a new engine using the given configuration.
func NewEnum4LinuxEngine(cfg *config.Config) *Enum4LinuxEngine {
    return &Enum4LinuxEngine{cfg: cfg}
}

// Run executes enum4linux-ng against the specified host. Additional options
// (e.g. `-U` to list users or `-G` to list groups) may be provided via opts.
// If opts is empty, `-A` is used for full enumeration.
func (e *Enum4LinuxEngine) Run(ctx context.Context, host string, opts []string) (*model.Enum4linuxResult, error) {
    if host == "" {
        return nil, fmt.Errorf("host is required")
    }
    bin := e.cfg.ToolPaths.Enum4linux
    if bin == "" {
        bin = "enum4linux-ng"
    }

    tmpFile, err := os.CreateTemp("", "enum4linux-*.json")
    if err != nil {
        return nil, fmt.Errorf("create temp file: %w", err)
    }
    tmpPath := tmpFile.Name()
    tmpFile.Close()
    defer os.Remove(tmpPath)

    args := []string{"-oJ", tmpPath}
    if len(opts) == 0 {
        args = append(args, "-A")
    } else {
        args = append(args, opts...)
    }
    args = append(args, host)

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        // try to read partial JSON anyway
    }

    dataBytes, err := os.ReadFile(tmpPath)
    if err != nil {
        return nil, fmt.Errorf("read enum4linux output: %w", err)
    }
    var data map[string]interface{}
    if len(dataBytes) > 0 {
        if err := json.Unmarshal(dataBytes, &data); err != nil {
            data = map[string]interface{}{"raw": string(dataBytes)}
        }
    }
    return &model.Enum4linuxResult{Host: host, Data: data}, nil
}
