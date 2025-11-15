
# rustygo

> Multifunctional recon & operator console in Go (with Rust-friendly design), wrapping modern tooling for internet-wide recon, internal AD/SMB/LDAP enumeration, and C2 payload orchestration — **for authorized security testing only**.

rustygo is meant to be the “brain” sitting on top of tools like:

- ProjectDiscovery stack (subfinder / httpx / dnsx / naabu / nuclei)
- enum4linux-ng, nbtstat/nbtscan, netexec, smbclient/smbmap
- ldapsearch + BloodHound JSON
- Havoc / Empire / Adaptix C2
- Metasploit (via scripted `msfconsole`)

It orchestrates scans, stores results in a structured format, and gives you a browser-based GUI to explore targets, internal hosts, directory data, and generated beacons.

---

## ⚠️ Legal / Ethical Notice

rustygo is built **exclusively for**:

- Red teams
- Blue teams running purple exercises
- Security researchers with **explicit written authorization**

**Do not** use this project against systems you do not own or have permission to test. You are responsible for complying with all applicable laws and rules of engagement.

---

## Features

### Internet-Facing Recon

- **Full recon pipeline**
  - Passive subdomain enum via:
    - `subfinder`, `assetfinder`, `crt.sh` & friends
  - DNS resolution & tech mapping:
    - `dnsx`, records (A/AAAA/CNAME/SRV/TXT/…)
  - Port scanning / service discovery:
    - `naabu` (TCP/UDP)
  - HTTP probing:
    - `httpx` (status, title, TLS, tech fingerprints)
  - Vulnerability templates:
    - `nuclei` for common misconfig & CVEs
- **Sync & async execution**
  - `rustygo run full -d example.com` (sync, JSON to stdout)
  - `rustygo serve` + GUI async jobs

### Windows / Internal Recon

- **SMB / Windows enumeration**
  - `enum4linux-ng` wrapper for:
    - users, groups, shares, sessions, policies (depending on flags)
  - NetBIOS info:
    - `nbtstat` (Windows) or `nbtscan` (Unix)
  - `netexec` integration:
    - `enum smb`/`winrm` modules via unified interface
  - SMB shares:
    - `smbclient` (parsed share list)
    - `smbmap` (raw output for advanced users)

### Directory & AD

- **LDAP search (`ldapsearch`)**
  - Flexible wrapper for common AD queries:
    - base DN + filter + attribute selection
  - Outputs structured entries with attributes.

- **BloodHound JSON summary**
  - Paste BloodHound graph JSON into the GUI.
  - Get:
    - node count
    - edge count
    - node type breakdown (User, Computer, Group, etc.)

### C2 & Payload Orchestration

- **Beacon generation helpers**
  - **Havoc**: shell out to local `havoc` client for beacon/payload creation.
  - **Empire**: talk to Empire’s REST API (Starkiller-style) to:
    - authenticate
    - create listener + stager from JSON config
  - **Adaptix**: request custom agents via Adaptix REST.

> rustygo doesn’t try to be a C2: it coordinates payload generation and tracks metadata, leaving live ops to Havoc / Empire / Adaptix.

- **Metasploit client (optional)**
  - Minimal wrapper around `msfconsole -x` for scripted runs.
  - Example: run auxiliary scanners from one place and store their output.

### Web GUI

`rustygo serve --addr :8080` gives you:

- **Recon control**
  - Start sync/async full recon jobs.
  - See job list (status, stage, progress).
  - Browse saved results.

- **Nice summaries**
  - Domain overview (subdomains, DNS, ports, HTTP, vulns).
  - “Top N” subdomains/ports/HTTP services.
  - Quick vulnerability sample.

- **Windows / internal tools**
  - Cards for:
    - enum4linux-ng host
    - NetBIOS IP enum
    - netexec module (`smb`, `winrm`, etc.)
    - SMB shares (host + creds + tool selection)

- **Directory / BloodHound**
  - LDAP form (host, base DN, filter, attrs, bind DN, LDAPS toggle).
  - BloodHound JSON paste box → node/edge/type summary.

- **Beacon helpers**
  - Havoc args input → output preview.
  - Empire config JSON → listener + stager.
  - Adaptix config JSON → agent ID + download URL.

All responses also show up in a “Raw JSON” pane for copy-paste into other tools.

---

## Installation

### Requirements

- OS: Linux or macOS (Windows WSL should also work)
- Go: **1.21+**
- (Optionally) Rust toolchain for future Rust-side agents
- External tools (depending on which modules you actually use):

  - Recon:
    - `subfinder`, `assetfinder`, `dnsx`, `httpx`, `naabu`, `nuclei`
  - Windows / internal:
    - `enum4linux-ng`, `nbtstat` or `nbtscan`, `netexec`, `smbclient`, `smbmap`
  - Directory:
    - `ldapsearch` (usually from `ldap-utils` / `openldap-clients`)
  - C2:
    - `havoc` client
    - Empire server + API
    - Adaptix server
  - Optional:
    - `msfconsole`

### Quick install (Linux-ish)

Clone and build:

```bash
# clone
git clone https://github.com/MKlolbullen/rustygo.git
cd rustygo

# build CLI binary
go build -o rustygo ./cmd/rustygo
````

You can put the binary on your PATH:

```bash
sudo mv rustygo /usr/local/bin/
```

### Example helper script

Save this as `scripts/install.sh` if you like (adapt packages for your distro):

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "[*] Installing basic dependencies (Debian/Ubuntu style)..."
sudo apt-get update
sudo apt-get install -y \
  golang-go git \
  ldap-utils smbclient \
  nbtscan

echo "[*] Cloning rustygo..."
if [ ! -d rustygo ]; then
  git clone https://github.com/MKlolbullen/rustygo.git
fi
cd rustygo

echo "[*] Building rustygo..."
go build -o rustygo ./cmd/rustygo

echo "[*] Done. Consider copying ./rustygo to /usr/local/bin"
```

Run it:

```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

---

## Configuration

rustygo reads config from:

```text

cp config.json ~/.config/rustygo/config.json

```

Example:

```json
{
  "tool_paths": {
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "dnsx": "dnsx",
    "httpx": "httpx",
    "naabu": "naabu",
    "nuclei": "nuclei",

    "enum4linux_ng": "enum4linux-ng",
    "nbtstat": "nbtscan",
    "netexec": "netexec",
    "smbclient": "smbclient",
    "smbmap": "smbmap",

    "ldapsearch": "ldapsearch",
    "havoc_client": "havoc",
    "msfconsole": "msfconsole"
  },
  "api_keys": {
    "shodan": "",
    "censys_id": "",
    "censys_secret": "",

    "empire_api_url": "https://empire.example.local:1337",
    "empire_user": "apiuser",
    "empire_pass": "apipass",
    "empire_api_token": "",

    "adaptix_api_url": "https://adaptix.example.local/api",
    "adaptix_username": "apiuser",
    "adaptix_password": "apipass"
  }
}
```

Leave paths empty to use the binaries from `$PATH`.

---

## Usage

### CLI

#### Full recon

```bash
# Synchronous full pipeline
rustygo run full -d example.com > recon.json
```

#### Subdomain enumeration

```bash
rustygo enum subdomains \
  -d example.com \
  -tools subfinder,assetfinder,crtsh \
  -timeout 2m \
  -json
```

#### Windows / internal enum

```bash
# enum4linux-ng
rustygo enum smb -h dc01.internal.local --opts "-U,-G"

# NetBIOS (nbtstat/nbtscan)
rustygo enum netbios -ip 10.0.0.5

# netexec
rustygo enum netexec \
  -module smb \
  -target 10.0.0.5 \
  -flags "--shares --local-auth"
```

> SMB shares enumeration (smbclient/smbmap) & LDAP are currently driven via the HTTP API / GUI.

#### Server / GUI

```bash
# start web UI + HTTP APIs
rustygo serve --addr :8080
```

Visit: `http://localhost:8080`

From there you can:

* Run sync/async recon jobs.
* Use SMB/NetBIOS/netexec/SMB shares forms.
* Run ldapsearch queries and paste BloodHound JSON for summaries.
* Generate C2 beacons/stagers/agents via forms.

#### Beacon helpers

```bash
# Havoc
rustygo beacon havoc --args "--windows-demon --ip 10.0.0.10 --port 443"

# Empire
rustygo beacon empire --config /path/to/empire-config.json

# Adaptix
rustygo beacon adaptix --config /path/to/adaptix-config.json
```

Configs are arbitrary JSON documents that your Empire/Adaptix integration understands (listener names, stager types, formats, etc.).

---

## Roadmap / TODO

rustygo is intentionally modular and still evolving. Some things on the radar:

### Recon / Discovery

* [ ] Web content discovery:

  * `ffuf` / `feroxbuster` integration with structured results.
* [ ] HTTP screenshotting & favicon hashing:

  * `gowitness`-style gallery view in GUI.
* [ ] Parameter & JS endpoint discovery:

  * Parameter hunting and JS parsing for richer web attack surface.

### Internal / AD / Identity

* [ ] Host profiles:

  * Unified “host profile” schema (processes, users, AV/EDR, network).
* [ ] Privilege escalation hinting:

  * Windows and Linux privesc *enumeration* (no auto-exploit).
* [ ] AD graph:

  * Imported BloodHound data visualized as a relationship graph.
  * High-value accounts / Tier 0 nodes flagged.

### Cloud

* [ ] Cloud recon modules:

  * AWS / Azure / GCP asset inventory (read-only).
  * Linking cloud assets to internet recon results.

### C2 & Agents

* [ ] Agent-side Rust components:

  * Host telemetry & privesc info, speaking rustygo’s JSON schemas.
* [ ] Stronger C2 integrations:

  * Deeper metadata sync with Havoc/Empire/Adaptix.
* [ ] Metasploit UI:

  * GUI card for running small msfconsole scripts and archiving results.

### UX / Glue

* [ ] Global search:

  * Search across hosts, subdomains, users, vulns, tags.
* [ ] Tagging:

  * Tag assets (`env=prod`, `crown_jewel=true`, `owned=true`) and filter.
* [ ] Playbooks:

  * Declarative “if HTTP service discovered → run nuclei+ffuf” automation with clear logging and manual approval.

---

## Contributing

PRs, issues, and ideas are welcome — especially:

* New wrappers for well-known tools (ProjectDiscovery, AD/LDAP, Windows).
* Better data models for hosts/credentials/paths.
* UI improvements that make large attack surfaces easier to reason about.

Just keep everything oriented toward **authorized** security work, with good OPSEC and minimal surprise behavior.

---

## License

TBD by the repo owner. Until then, treat this as “look but don’t ship as a product” unless explicitly licensed.

```
::contentReference[oaicite:0]{index=0}
```
