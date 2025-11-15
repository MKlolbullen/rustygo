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

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/recon"
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
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `rustygo - multi-phase recon framework

Usage:
  rustygo enum subdomains [options]

Commands:
  enum subdomains   Passive subdomain enumeration via multiple sources
`)
}

func handleEnum(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "subdomains":
		enumSubdomains(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func enumSubdomains(args []string) {
	fs := flag.NewFlagSet("enum subdomains", flag.ExitOnError)
	domain := fs.String("d", "", "target domain")
	toolsStr := fs.String("tools", "subfinder,assetfinder,crtsh", "comma-separated tools")
	timeout := fs.Duration("timeout", 120*time.Second, "overall timeout")
	jsonOut := fs.Bool("json", true, "output JSON (one object per line)")
	fs.Parse(args)

	if *domain == "" {
		log.Fatalf("domain (-d) is required")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	var tools []recon.SubenumTool
	for _, t := range strings.Split(*toolsStr, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		tools = append(tools, recon.SubenumTool(t))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	engine := recon.NewSubenumEngine(cfg)
	results, err := engine.Run(ctx, recon.SubenumOptions{
		Domain: *domain,
		Tools:  tools,
	})
	if err != nil {
		log.Printf("warning: enumeration completed with error: %v", err)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				log.Fatalf("encode json: %v", err)
			}
		}
	} else {
		for _, r := range results {
			fmt.Println(r.Domain)
		}
	}
}
