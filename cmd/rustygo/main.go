package main

import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/MKlolbullen/rustygo/internal/config"
    "github.com/MKlolbullen/rustygo/internal/c2"
    "github.com/MKlolbullen/rustygo/internal/pipeline"
    "github.com/MKlolbullen/rustygo/internal/recon"
    "github.com/MKlolbullen/rustygo/internal/server"
    "github.com/MKlolbullen/rustygo/internal/windows"
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
    case "beacon":
        handleBeacon(os.Args[2:])
    default:
        usage()
        os.Exit(1)
    }
}

func usage() {
    fmt.Fprintf(os.Stderr, `rustygo - multifunctional recon tool

Usage:
  rustygo enum subdomains [options]      Perform passive subdomain enumeration
  rustygo enum smb -h <host> [--opts options]    Enumerate Windows/Samba using enum4linux-ng
  rustygo enum netbios -ip <ip>                  Look up NetBIOS names with nbtstat/nbtscan
  rustygo enum netexec -module <mod> -target <host> [--flags flags]  Run a netexec module
  rustygo run full -d <domain>                  Run full recon pipeline synchronously
  rustygo serve [--addr <host:port>]            Start HTTP API and GUI server

  # Beacon generation for C2 frameworks
  rustygo beacon havoc --args "<flags>"         Generate a beacon using Havoc C2
  rustygo beacon empire --config <file>         Generate an Empire stager (via Starkiller API)
  rustygo beacon adaptix --config <file>        Generate an Adaptix agent

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
    case "smb":
        enumSMB(args[1:])
    case "netbios":
        enumNetBIOS(args[1:])
    case "netexec":
        enumNetexec(args[1:])
    default:
        usage()
        os.Exit(1)
    }
}

// handleBeacon dispatches beacon subcommands. Usage:
//   rustygo beacon havoc --args "--windows-demon --ip 1.2.3.4 --port 443"
//   rustygo beacon empire --config /path/to/config.json
//   rustygo beacon adaptix --config /path/to/config.json
func handleBeacon(args []string) {
    if len(args) < 1 {
        usage()
        os.Exit(1)
    }
    switch args[0] {
    case "havoc":
        beaconHavoc(args[1:])
    case "empire":
        beaconEmpire(args[1:])
    case "adaptix":
        beaconAdaptix(args[1:])
    default:
        usage()
        os.Exit(1)
    }
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
    res, err := p.Run(ctx, pipeline.FullOptions{Domain: *domain}, nil)
    if err != nil {
        log.Fatalf("pipeline error: %v", err)
    }
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    enc.Encode(res)
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

// enumSMB runs enum4linux-ng
func enumSMB(args []string) {
    fs := flag.NewFlagSet("enum smb", flag.ExitOnError)
    host := fs.String("h", "", "target host (IP or hostname)")
    optsStr := fs.String("opts", "", "comma-separated enum4linux-ng options (e.g. -U,-G)")
    fs.Parse(args)

    if *host == "" {
        log.Fatalf("host (-h) is required")
    }

    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }

    var opts []string
    if *optsStr != "" {
        for _, o := range strings.Split(*optsStr, ",") {
            o = strings.TrimSpace(o)
            if o != "" {
                opts = append(opts, o)
            }
        }
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    eng := windows.NewEnum4LinuxEngine(cfg)
    res, err := eng.Run(ctx, *host, opts)
    if err != nil {
        log.Fatalf("enum4linux-ng error: %v", err)
    }
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    enc.Encode(res)
}

// enumNetBIOS runs nbtstat/nbtscan
func enumNetBIOS(args []string) {
    fs := flag.NewFlagSet("enum netbios", flag.ExitOnError)
    ip := fs.String("ip", "", "target IP address")
    fs.Parse(args)

    if *ip == "" {
        log.Fatalf("ip is required")
    }

    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    scanner := windows.NewNetBIOSScanner(cfg)
    res, err := scanner.Scan(ctx, *ip)
    if err != nil {
        log.Fatalf("netbios scan error: %v", err)
    }
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    enc.Encode(res)
}

// enumNetexec runs a netexec module
func enumNetexec(args []string) {
    fs := flag.NewFlagSet("enum netexec", flag.ExitOnError)
    module := fs.String("module", "", "netexec module (e.g. smb, winrm)")
    target := fs.String("target", "", "target host")
    flagsStr := fs.String("flags", "", "additional flags passed to netexec")
    fs.Parse(args)

    if *module == "" || *target == "" {
        log.Fatalf("module and target are required")
    }

    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }

    var flags []string
    if *flagsStr != "" {
        fields := strings.Fields(*flagsStr)
        flags = append(flags, fields...)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    eng := windows.NewNetexecEngine(cfg)
    res, err := eng.Run(ctx, *module, *target, flags)
    if err != nil {
        log.Fatalf("netexec error: %v", err)
    }
    enc := json.NewEncoder(os.Stdout)
    enc.SetIndent("", "  ")
    enc.Encode(res)
}

// beaconHavoc shells out to havoc client (local)
func beaconHavoc(args []string) {
    fs := flag.NewFlagSet("beacon havoc", flag.ExitOnError)
    argStr := fs.String("args", "", "arguments passed to havoc client")
    fs.Parse(args)

    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }
    client := c2.NewHavocClient(cfg)

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    out, err := client.GenerateBeacon(ctx, *argStr)
    if err != nil {
        log.Fatalf("havoc beacon error: %v", err)
    }
    fmt.Println(out)
}

// beaconEmpire uses Empire REST API (Starkiller-style)
func beaconEmpire(args []string) {
    fs := flag.NewFlagSet("beacon empire", flag.ExitOnError)
    cfgPath := fs.String("config", "", "JSON config file for Empire stager/listener")
    fs.Parse(args)
    if *cfgPath == "" {
        log.Fatalf("config is required")
    }

    data, err := os.ReadFile(*cfgPath)
    if err != nil {
        log.Fatalf("read config: %v", err)
    }
    var cfgData map[string]interface{}
    if err := json.Unmarshal(data, &cfgData); err != nil {
        log.Fatalf("parse config json: %v", err)
    }

    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }

    empireCfg := c2.ConfigFromGlobal(cfg)
    client := c2.NewEmpireClient(empireCfg)

    // simple flow: login, ensure listener, generate stager
    if err := client.Login(); err != nil {
        log.Fatalf("empire login: %v", err)
    }
    listenerName, stager, err := client.GenerateStagerFromConfig(cfgData)
    if err != nil {
        log.Fatalf("empire stager error: %v", err)
    }

    fmt.Printf("Listener: %s\n", listenerName)
    fmt.Printf("Stager:\n%s\n", stager)
}

// beaconAdaptix hits Adaptix REST
func beaconAdaptix(args []string) {
    fs := flag.NewFlagSet("beacon adaptix", flag.ExitOnError)
    cfgPath := fs.String("config", "", "JSON config file with Adaptix agent parameters")
    fs.Parse(args)
    if *cfgPath == "" {
        log.Fatalf("config is required")
    }
    data, err := os.ReadFile(*cfgPath)
    if err != nil {
        log.Fatalf("read config: %v", err)
    }
    var cfgDoc map[string]interface{}
    if err := json.Unmarshal(data, &cfgDoc); err != nil {
        log.Fatalf("parse config json: %v", err)
    }

    globalCfg, err := config.Load()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }

    acfg := c2.AdaptixConfigFromGlobal(globalCfg)
    client := c2.NewAdaptixClient(acfg)
    if err := client.Login(); err != nil {
        log.Fatalf("adaptix login: %v", err)
    }

    id, url, err := client.GenerateAgent(cfgDoc)
    if err != nil {
        log.Fatalf("adaptix generate agent: %v", err)
    }
    fmt.Printf("Adaptix agent ID: %s\nDownload URL: %s\n", id, url)
}