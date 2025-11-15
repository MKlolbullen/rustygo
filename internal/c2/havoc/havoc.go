package c2

import (
    "context"
    "fmt"
    "strings"

    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/executil"
)

// HavocClient is a thin wrapper around the local Havoc client binary.
// It simply shells out and returns stdout/stderr.
type HavocClient struct {
    bin string
}

func NewHavocClient(cfg *config.Config) *HavocClient {
    bin := cfg.ToolPaths.HavocClient
    if bin == "" {
        bin = "havoc"
    }
    return &HavocClient{bin: bin}
}

func (c *HavocClient) GenerateBeacon(ctx context.Context, args string) (string, error) {
    fields := []string{}
    if strings.TrimSpace(args) != "" {
        fields = append(fields, strings.Fields(args)...)
    }
    res := executil.Run(ctx, c.bin, fields...)
    if res.Err != nil {
        return "", fmt.Errorf("havoc client error: %w\nstderr: %s", res.Err, string(res.Stderr))
    }
    return string(res.Stdout), nil
}
