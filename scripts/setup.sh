#!/usr/bin/env bash
set -euo pipefail

# Rustygo setup wizard
# --------------------
# This script:
#  - Checks for Go, Node, npm, nmap
#  - Builds the Go backend
#  - Installs + builds the React/Vite UI under ./ui
#  - Interactively configures integrations:
#      * Metasploit (msfrpc)
#      * Havoc
#      * Empire
#      * Adaptix
#  - Writes config/integrations.json with the selected options
#
# All offensive tooling MUST only be used in environments where you have
# explicit permission. Don’t be That Person™.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$REPO_ROOT/config"
INTEGRATIONS_JSON="$CONFIG_DIR/integrations.json"

echo "== Rustygo setup wizard =="
echo "Repository root: $REPO_ROOT"
echo

# --- Helpers ---------------------------------------------------------

prompt_yn() {
  local prompt="$1"
  local default="${2:-y}"
  local answer

  while true; do
    if [[ "$default" == "y" ]]; then
      read -r -p "$prompt [Y/n] " answer || true
      answer="${answer:-y}"
    else
      read -r -p "$prompt [y/N] " answer || true
      answer="${answer:-n}"
    fi
    case "$answer" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

prompt_default() {
  local prompt="$1"
  local default="$2"
  local answer
  read -r -p "$prompt [$default] " answer || true
  echo "${answer:-$default}"
}

check_cmd() {
  local cmd="$1"
  local friendly="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "!! Missing dependency: $friendly ($cmd not found on PATH)"
    return 1
  fi
  return 0
}

# --- Dependency checks ----------------------------------------------

echo "== Checking core dependencies =="

missing_any=0

if ! check_cmd go "Go toolchain"; then
  missing_any=1
fi

if ! check_cmd node "Node.js"; then
  missing_any=1
fi

if ! check_cmd npm "npm (Node package manager)"; then
  missing_any=1
fi

if ! check_cmd nmap "nmap (network scanner)"; then
  missing_any=1
fi

if [[ $missing_any -eq 1 ]]; then
  cat <<EOF

Some core dependencies are missing.

You need at least:
  - go
  - node
  - npm
  - nmap

Install them via your OS package manager (apt, dnf, pacman, brew, etc.),
then re-run this script.

EOF
  exit 1
fi

echo "All core deps present."
echo

# --- Build Go backend -----------------------------------------------

echo "== Building Go backend =="

cd "$REPO_ROOT"
if [[ ! -f "go.mod" ]]; then
  echo "!! No go.mod found in $REPO_ROOT. Are you in the Rustygo repo?"
  exit 1
fi

echo "+ go build ./cmd/rustygo"
go build ./cmd/rustygo

echo "Go backend built (binary: ./rustygo)"
echo

# --- Setup UI (React/Vite) ------------------------------------------

UI_DIR="$REPO_ROOT/ui"

if [[ ! -d "$UI_DIR" ]]; then
  echo "!! UI directory $UI_DIR not found."
  echo "   Create it first or adjust this script."
  exit 1
fi

echo "== Setting up UI (React/Vite) =="
cd "$UI_DIR"

if [[ ! -f "package.json" ]]; then
  echo "!! No package.json found in $UI_DIR."
  echo "   Make sure the UI scaffold is created (package.json, tsconfig, etc)."
  exit 1
fi

echo "+ npm install"
npm install

echo "+ npm run build"
npm run build

echo "UI built. You can run dev mode later with: npm run dev"
echo

# --- Integration configuration --------------------------------------

mkdir -p "$CONFIG_DIR"

echo "== Integration configuration =="
echo "We will now configure optional integrations. These do NOT install the tools,"
echo "they just record how to talk to them. You are responsible for installing"
echo "Metasploit/Havoc/Empire/Adaptix and making sure commands are on PATH."
echo

# Start with a basic JSON structure in shell variables.
# We'll assemble a final JSON at the end.
msf_enabled=false
havoc_enabled=false
empire_enabled=false
adaptix_enabled=false

msf_rpc_host=""
msf_rpc_port=""
msf_rpc_user=""
msf_rpc_pass=""
msf_cmd=""

havoc_client_path=""
havoc_server_url=""

empire_api_url=""
empire_user=""
empire_pass=""

adaptix_api_url=""
adaptix_api_token=""

# --- Metasploit -----------------------------------------------------

if prompt_yn "Enable Metasploit (msfrpc) integration?" "y"; then
  msf_enabled=true

  if command -v msfconsole >/dev/null 2>&1; then
    echo "Found msfconsole at: $(command -v msfconsole)"
    msf_cmd="$(command -v msfconsole)"
  else
    echo "msfconsole not found on PATH."
    msf_cmd="$(prompt_default "Path to msfconsole (or msfrpcd helper)" "/usr/bin/msfconsole")"
  fi

  echo
  echo "Metasploit RPC settings (this assumes you will run msfrpcd separately)."
  msf_rpc_host="$(prompt_default "Metasploit RPC host" "127.0.0.1")"
  msf_rpc_port="$(prompt_default "Metasploit RPC port" "55553")"
  msf_rpc_user="$(prompt_default "Metasploit RPC username" "msf")"
  msf_rpc_pass="$(prompt_default "Metasploit RPC password" "password")"

  echo
  echo "NOTE:"
  echo "  You must start msfrpcd (or equivalent RPC service) yourself, e.g.:"
  echo "    msfrpcd -U \"$msf_rpc_user\" -P \"$msf_rpc_pass\" -S -p $msf_rpc_port -a $msf_rpc_host"
  echo
else
  echo "Metasploit integration disabled."
fi
echo

# --- Havoc ----------------------------------------------------------

if prompt_yn "Enable Havoc C2 integration?" "n"; then
  havoc_enabled=true

  if command -v havoc >/dev/null 2>&1; then
    echo "Found havoc at: $(command -v havoc)"
    havoc_client_path="$(command -v havoc)"
  else
    havoc_client_path="$(prompt_default "Path to Havoc client binary" "/opt/havoc/havoc")"
  fi

  havoc_server_url="$(prompt_default "Havoc server URL" "https://127.0.0.1:40056")"

  echo
  echo "You are responsible for running the Havoc server and configuring TLS/certs."
  echo
else
  echo "Havoc integration disabled."
fi
echo

# --- Empire ---------------------------------------------------------

if prompt_yn "Enable Empire integration?" "n"; then
  empire_enabled=true

  empire_api_url="$(prompt_default "Empire API URL" "https://127.0.0.1:1337")"
  empire_user="$(prompt_default "Empire username" "empireadmin")"
  empire_pass="$(prompt_default "Empire password" "Password123!")"

  echo
  echo "Make sure the Empire REST API is enabled and listening on the given URL."
  echo
else
  echo "Empire integration disabled."
fi
echo

# --- Adaptix --------------------------------------------------------

if prompt_yn "Enable Adaptix integration?" "n"; then
  adaptix_enabled=true

  adaptix_api_url="$(prompt_default "Adaptix API URL" "https://127.0.0.1:8443")"
  adaptix_api_token="$(prompt_default "Adaptix API token" "changeme-token")"

  echo
  echo "Ensure the Adaptix server is up and reachable with the provided token."
  echo
else
  echo "Adaptix integration disabled."
fi
echo

# --- Write integrations.json ----------------------------------------

echo "== Writing $INTEGRATIONS_JSON =="

cat >"$INTEGRATIONS_JSON" <<EOF
{
  "metasploit": {
    "enabled": $msf_enabled,
    "rpc_host": "$msf_rpc_host",
    "rpc_port": "$msf_rpc_port",
    "rpc_user": "$msf_rpc_user",
    "rpc_pass": "$msf_rpc_pass",
    "msfconsole_path": "$msf_cmd"
  },
  "havoc": {
    "enabled": $havoc_enabled,
    "client_path": "$havoc_client_path",
    "server_url": "$havoc_server_url"
  },
  "empire": {
    "enabled": $empire_enabled,
    "api_url": "$empire_api_url",
    "username": "$empire_user",
    "password": "$empire_pass"
  },
  "adaptix": {
    "enabled": $adaptix_enabled,
    "api_url": "$adaptix_api_url",
    "api_token": "$adaptix_api_token"
  }
}
EOF

echo "Wrote integrations config."
echo

# --- Summary --------------------------------------------------------

echo "== Setup complete (base level) =="
echo
echo "Backend binary: $REPO_ROOT/rustygo"
echo "UI build:       $UI_DIR/dist"
echo "Integrations:   $INTEGRATIONS_JSON"
echo
echo "To run the Go server (example):"
echo "  cd \"$REPO_ROOT\""
echo "  ./rustygo   # or go run ./cmd/rustygo"
echo
echo "To run the UI in dev mode (separate terminal):"
echo "  cd \"$UI_DIR\""
echo "  npm run dev"
echo
echo "Metasploit / Havoc / Empire / Adaptix integrations will only work once"
echo "those tools are installed and their services are running with the"
echo "endpoints you configured."
echo
echo "Remember: use this framework ONLY in environments where you have explicit"
echo "permission to test. Offensive tooling is a scalpel, not a toy."