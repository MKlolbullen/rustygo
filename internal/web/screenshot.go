package web

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/executil"
    "github.com/MKlolbullen/rustygo/internal/model"
)

// ScreenshotEngine wraps a generic screenshot tool (e.g. gowitness).
type ScreenshotEngine struct {
    cfg    *config.Config
    outDir string
}

func NewScreenshotEngine(cfg *config.Config, outDir string) *ScreenshotEngine {
    return &ScreenshotEngine{cfg: cfg, outDir: outDir}
}

// CaptureSingle runs the screenshot tool for a single URL and returns metadata.
func (e *ScreenshotEngine) CaptureSingle(ctx context.Context, url string) (*model.WebScreenshot, error) {
    if url == "" {
        return nil, fmt.Errorf("url is required")
    }
    bin := e.cfg.ToolPaths.ScreenshotTool
    if bin == "" {
        bin = "gowitness" // default guess
    }

    if err := os.MkdirAll(e.outDir, 0o755); err != nil {
        return nil, fmt.Errorf("create screenshot dir: %w", err)
    }

    // We won't rely on exact gowitness flags; keep it generic:
    // e.g., gowitness single --url URL --destination DIR
    args := []string{"single", "--url", url, "--destination", e.outDir}

    res := executil.Run(ctx, bin, args...)
    if res.Err != nil {
        return nil, fmt.Errorf("screenshot tool error: %w\nstderr: %s", res.Err, string(res.Stderr))
    }

    // Heuristic: assume it writes a PNG named after host in outDir
    fname := sanitizeFilename(url) + ".png"
    path := filepath.Join(e.outDir, fname)

    ws := &model.WebScreenshot{
        URL:            url,
        ScreenshotPath: path,
    }
    return ws, nil
}

// sanitizeFilename turns a URL into a filesystem-ish name.
func sanitizeFilename(url string) string {
    s := strings.TrimPrefix(url, "http://")
    s = strings.TrimPrefix(s, "https://")
    s = strings.TrimRight(s, "/")
    s = strings.ReplaceAll(s, "/", "_")
    s = strings.ReplaceAll(s, ":", "_")
    return s
}
