package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"path/filepath"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/recon"
	"github.com/MKlolbullen/rustygo/internal/server"
)


func main() {
    log.SetFlags(0)

    if len(os.Args) < 2 {
        usage()
        os.Exit(1)
    }

    switch os.Args[1] {
    case "enum":
        handleEnum(os.Args[2:])
    case "run":
        handleRun(os.Args[2:])
    case "serve":
        handleServe(os.Args[2:])
    default:
        usage()
        os.Exit(1)
    }
}

func usage() {
    fmt.Fprintf(os.Stderr, `rustygo - recon framework

Usage:
  rustygo enum subdomains [options]
  rustygo run full -d example.com
  rustygo serve [--addr :8080]

`)
}

func handleRun(args []string) {
    if len(args) < 1 {
        usage()
        os.Exit(1)
    }
    switch args[0] {
    case "full":
        runFull(args[1:])
    default:
        usage()
        os.Exit(1)
    }
}

func runFull(args []string) {
    fs := flag.NewFlagSet("run full", flag.ExitOnError)
    domain := fs.String("d", "", "target domain")
    timeout := fs.Duration("timeout", 15*time.Minute, "overall timeout")
    fs.Parse(args)

    if *domain == "" {
        log.Fatalf("domain (-d) is required")
    }

    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), *timeout)
    defer cancel()

    p := pipeline.NewFullPipeline(cfg)
    res, err := p.Run(ctx, pipeline.FullOptions{Domain: *domain})
    if err != nil {
        log.Fatalf("pipeline error: %v", err)
    }
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    enc.Encode(res)
}

func handleServe(args []string) {
    fs := flag.NewFlagSet("serve", flag.ExitOnError)
    addr := fs.String("addr", ":8080", "listen address")
    fs.Parse(args)

    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }
    home, _ := os.UserHomeDir()
    dataDir := filepath.Join(home, ".local", "share", "rustygo", "workspaces")

    srv := server.New(cfg, dataDir)
    if err := srv.ListenAndServe(*addr); err != nil {
        log.Fatalf("serve: %v", err)
    }
}
