package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MKlolbullen/rustygo/internal/ad"
	"github.com/MKlolbullen/rustygo/internal/c2"
	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/model"
	"github.com/MKlolbullen/rustygo/internal/pipeline"
	"github.com/MKlolbullen/rustygo/internal/privesc"
	"github.com/MKlolbullen/rustygo/internal/windows"
)

type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobError     JobStatus = "error"
)

type Job struct {
	ID        string             `json:"id"`
	Domain    string             `json:"domain"`
	Status    JobStatus          `json:"status"`
	Progress  int                `json:"progress"`
	Stage     string             `json:"stage,omitempty"`
	Error     string             `json:"error,omitempty"`
	Result    *model.ReconResult `json:"result,omitempty"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

type Server struct {
	cfg     *config.Config
	mux     *http.ServeMux
	dataDir string

	mu   sync.Mutex
	jobs map[string]*Job
}

func New(cfg *config.Config, dataDir string) *Server {
	mux := http.NewServeMux()
	s := &Server{
		cfg:     cfg,
		mux:     mux,
		dataDir: dataDir,
		jobs:    make(map[string]*Job),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Full recon APIs
	s.mux.HandleFunc("/api/run/full", s.handleRunFull)

	// Job APIs
	s.mux.HandleFunc("/api/jobs/full", s.handleCreateJob)
	s.mux.HandleFunc("/api/jobs", s.handleJobs)
	s.mux.HandleFunc("/api/jobs/", s.handleJob)

	// Saved recon results
	s.mux.HandleFunc("/api/results", s.handleListResults)
	s.mux.HandleFunc("/api/results/", s.handleGetResult)

	// Windows / AD / network enumeration
	s.mux.HandleFunc("/api/enum/smb", s.handleEnumSMB)             // enum4linux-ng
	s.mux.HandleFunc("/api/enum/netbios", s.handleEnumNetBIOS)     // nbtstat/nbtscan
	s.mux.HandleFunc("/api/enum/netexec", s.handleEnumNetexec)     // netexec
	s.mux.HandleFunc("/api/enum/smbshares", s.handleEnumSMBShares) // smbclient/smbmap shares

	// LDAP & BloodHound
	s.mux.HandleFunc("/api/ad/ldap", s.handleADLDAP)
	s.mux.HandleFunc("/api/ad/bloodhound/summary", s.handleBloodHoundSummary)
	s.mux.HandleFunc("/api/ad/bloodhound/graph", s.handleBloodHoundGraph)

	// Host profile & privesc hints
	s.mux.HandleFunc("/api/host/profile/analyze", s.handleHostProfileAnalyze)

	// Beacon generation
	s.mux.HandleFunc("/api/beacon/havoc", s.handleBeaconHavoc)
	s.mux.HandleFunc("/api/beacon/empire", s.handleBeaconEmpire)
	s.mux.HandleFunc("/api/beacon/adaptix", s.handleBeaconAdaptix)

	// GUI
	s.mux.HandleFunc("/", s.handleIndex)
}

func (s *Server) ListenAndServe(addr string) error {
	log.Printf("rustygo GUI listening on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ---------- Full recon (sync) ----------

func (s *Server) handleRunFull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	type reqBody struct {
		Domain string `json:"domain"`
	}
	var body reqBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Domain == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()

	p := pipeline.NewFullPipeline(s.cfg)
	res, err := p.Run(ctx, pipeline.FullOptions{Domain: body.Domain}, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("pipeline error: %v", err), http.StatusInternalServerError)
		return
	}

	if err := s.saveResult(res); err != nil {
		log.Printf("save result error: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// ---------- Job handling (async full recon) ----------

func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	type reqBody struct {
		Domain string `json:"domain"`
	}
	var body reqBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Domain == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	job := &Job{
		ID:        randomID(),
		Domain:    body.Domain,
		Status:    JobPending,
		Progress:  0,
		Stage:     "queued",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	s.mu.Lock()
	s.jobs[job.ID] = job
	s.mu.Unlock()

	go s.runJob(job.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) runJob(id string) {
	s.mu.Lock()
	job, ok := s.jobs[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	job.Status = JobRunning
	job.Stage = "starting"
	job.Progress = 1
	job.UpdatedAt = time.Now().UTC()
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	p := pipeline.NewFullPipeline(s.cfg)

	progressFn := func(stage string, pct int) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if j, exists := s.jobs[id]; exists {
			j.Stage = stage
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
			j.Progress = pct
			j.UpdatedAt = time.Now().UTC()
		}
	}

	res, err := p.Run(ctx, pipeline.FullOptions{Domain: job.Domain}, progressFn)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		job.Status = JobError
		job.Error = err.Error()
		job.Stage = "error"
		job.Progress = 100
		job.UpdatedAt = time.Now().UTC()
		return
	}

	job.Status = JobCompleted
	job.Stage = "completed"
	job.Progress = 100
	job.Result = res
	job.UpdatedAt = time.Now().UTC()

	if err := s.saveResult(res); err != nil {
		log.Printf("save result for job %s: %v", id, err)
	}
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []*Job
	for _, j := range s.jobs {
		out = append(out, j)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[id]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(j)
}

// ---------- Saved result handling ----------

func (s *Server) resultFilePath(domain string, startedAt time.Time) string {
	safe := domain
	if safe == "" {
		safe = "unknown"
	}
	filename := fmt.Sprintf("%s-%d.json", safe, startedAt.Unix())
	return filepath.Join(s.dataDir, filename)
}

func (s *Server) saveResult(res *model.ReconResult) error {
	if err := os.MkdirAll(s.dataDir, 0o755); err != nil {
		return err
	}
	path := s.resultFilePath(res.Domain, res.StartedAt)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(res)
}

func (s *Server) handleListResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type item struct {
		File string `json:"file"`
	}
	var out []item
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		out = append(out, item{File: e.Name()})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleGetResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/results/")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.dataDir, name)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, f)
}

// ---------- Windows / AD / network enumeration handlers ----------

// POST /api/enum/smb { "host": "x", "opts": "-U,-G" }
func (s *Server) handleEnumSMB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Host string `json:"host"`
		Opts string `json:"opts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Host == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	var opts []string
	if body.Opts != "" {
		for _, o := range strings.Split(body.Opts, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				opts = append(opts, o)
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	eng := windows.NewEnum4LinuxEngine(s.cfg)
	res, err := eng.Run(ctx, body.Host, opts)
	if err != nil {
		http.Error(w, "enum4linux error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// POST /api/enum/netbios { "ip": "x.x.x.x" }
func (s *Server) handleEnumNetBIOS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()

	scanner := windows.NewNetBIOSScanner(s.cfg)
	res, err := scanner.Scan(ctx, body.IP)
	if err != nil {
		http.Error(w, "netbios error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// POST /api/enum/netexec { "module": "smb", "target": "host", "flags": "--shares" }
func (s *Server) handleEnumNetexec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Module string `json:"module"`
		Target string `json:"target"`
		Flags  string `json:"flags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		body.Module == "" || body.Target == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	var flags []string
	if body.Flags != "" {
		flags = append(flags, strings.Fields(body.Flags)...)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	eng := windows.NewNetexecEngine(s.cfg)
	res, err := eng.Run(ctx, body.Module, body.Target, flags)
	if err != nil {
		http.Error(w, "netexec error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// POST /api/enum/smbshares { "host": "...", "username": "...", "password": "...", "domain": "...", "tool": "smbclient|smbmap" }
func (s *Server) handleEnumSMBShares(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Host     string `json:"host"`
		Username string `json:"username"`
		Password string `json:"password"`
		Domain   string `json:"domain"`
		Tool     string `json:"tool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Host == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	eng := windows.NewSMBEnumerator(s.cfg)
	res, err := eng.EnumShares(ctx, windows.SMBEnumOptions{
		Host:     body.Host,
		Username: body.Username,
		Password: body.Password,
		Domain:   body.Domain,
		Tool:     body.Tool,
	})
	if err != nil {
		http.Error(w, "smb shares error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// ---------- LDAP & BloodHound ----------

// POST /api/ad/ldap { "host": "...", "base_dn": "...", "filter": "(objectClass=user)", "attrs": "cn,sAMAccountName", "bind_dn": "...", "password": "...", "use_ldaps": true }
func (s *Server) handleADLDAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Host     string `json:"host"`
		BaseDN   string `json:"base_dn"`
		Filter   string `json:"filter"`
		Attrs    string `json:"attrs"`
		BindDN   string `json:"bind_dn"`
		Password string `json:"password"`
		UseLDAPS bool   `json:"use_ldaps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Host == "" || body.BaseDN == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	var attrs []string
	if strings.TrimSpace(body.Attrs) != "" {
		for _, a := range strings.Split(body.Attrs, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				attrs = append(attrs, a)
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	engine := ad.NewLDAPEngine(s.cfg)
	res, err := engine.Search(ctx, ad.LDAPOptions{
		Host:       body.Host,
		BaseDN:     body.BaseDN,
		Filter:     body.Filter,
		Attributes: attrs,
		BindDN:     body.BindDN,
		Password:   body.Password,
		UseLDAPS:   body.UseLDAPS,
	})
	if err != nil {
		http.Error(w, "ldap error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// POST /api/ad/bloodhound/summary { "json": "<full bloodhound json string>" }
func (s *Server) handleBloodHoundSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		JSON string `json:"json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.JSON) == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	engine := ad.NewBloodHoundEngine()
	summary, err := engine.SummarizeJSONBytes([]byte(body.JSON))
	if err != nil {
		http.Error(w, "bloodhound parse error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

// POST /api/ad/bloodhound/graph { "json": "<full bloodhound JSON>" }
func (s *Server) handleBloodHoundGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		JSON string `json:"json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.JSON) == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	graph, err := ad.ParseBloodHoundGraph([]byte(body.JSON))
	if err != nil {
		http.Error(w, "bloodhound graph parse error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(graph)
}

// ---------- Host profile & privesc ----------

// POST /api/host/profile/analyze
// Body: { "profile": { HostProfile ... } }
func (s *Server) handleHostProfileAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Profile *model.HostProfile `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Profile == nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	hints := privesc.AnalyzeHost(body.Profile)

	resp := struct {
		Profile *model.HostProfile  `json:"profile"`
		Hints   []model.PrivescHint `json:"hints"`
	}{
		Profile: body.Profile,
		Hints:   hints,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------- Beacon handlers ----------

// POST /api/beacon/havoc { "args": "--windows-demon ..." }
func (s *Server) handleBeaconHavoc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Args string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	client := c2.NewHavocClient(s.cfg)
	out, err := client.GenerateBeacon(ctx, body.Args)
	if err != nil {
		http.Error(w, "havoc error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": out})
}

// POST /api/beacon/empire { raw Empire config JSON }
func (s *Server) handleBeaconEmpire(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var cfgDoc map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&cfgDoc); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ecfg := c2.ConfigFromGlobal(s.cfg)
	client := c2.NewEmpireClient(ecfg)
	if err := client.Login(); err != nil {
		http.Error(w, "empire login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	listener, stager, err := client.GenerateStagerFromConfig(cfgDoc)
	if err != nil {
		http.Error(w, "empire stager: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"listener": listener,
		"stager":   stager,
	})
}

// POST /api/beacon/adaptix { "config": { ... } }
func (s *Server) handleBeaconAdaptix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Config map[string]interface{} `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	acfg := c2.AdaptixConfigFromGlobal(s.cfg)
	client := c2.NewAdaptixClient(acfg)
	if err := client.Login(); err != nil {
		http.Error(w, "adaptix login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	id, url, err := client.GenerateAgent(body.Config)
	if err != nil {
		http.Error(w, "adaptix generate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id":  id,
		"url": url,
	})
}

// ---------- GUI ----------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

const indexHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>rustygo</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#020617; color:#e5e7eb; margin:0; padding:20px; }
    h1 { margin-bottom: 0.25rem; }
    h2 { margin-top:0; }
    .card { background:#020617; border:1px solid #1f2937; border-radius:14px; padding:16px; margin-bottom:16px; }
    input, button, textarea { padding:8px; border-radius:8px; border:1px solid #4b5563; background:#020617; color:#e5e7eb; }
    button { cursor:pointer; }
    button:hover { border-color:#9ca3af; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; background:#111827; font-size:12px; margin-left:8px; }
    table { width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }
    th, td { padding:6px 8px; border-bottom:1px solid #1f2937; text-align:left; }
    tr:hover { background:#030712; }
    .row { display:flex; flex-wrap:wrap; gap:16px; }
    .col { flex:1 1 320px; }
    pre { background:#020617; border-radius:8px; border:1px solid #1f2937; padding:8px; font-size:12px; }
    textarea { width:100%; }
  </style>
</head>
<body>
  <h1>rustygo</h1>
  <p>Multi-phase recon & operator console (Go + Rust). For authorized testing only.</p>

  <div class="row">
    <div class="col">
      <div class="card">
        <h2>Run full recon (sync)</h2>
        <input id="domain" placeholder="example.com" />
        <button onclick="runSync()">Run</button>
        <span id="status" class="pill"></span>
      </div>

      <div class="card">
        <h2>Asynchronous recon job</h2>
        <input id="async-domain" placeholder="example.com" />
        <button onclick="startJob()">Start Job</button>
        <span id="async-status" class="pill"></span>
      </div>

      <div class="card">
        <h2>Enumerations</h2>

        <h3>SMB / enum4linux-ng</h3>
        <input id="smb-host" placeholder="host or IP" />
        <input id="smb-opts" placeholder="-U,-G,-S (optional)" />
        <button onclick="enumSMB()">Run SMB Enum</button>

        <h3>NetBIOS</h3>
        <input id="netbios-ip" placeholder="IP address" />
        <button onclick="enumNetBIOS()">Run NetBIOS Enum</button>

        <h3>Netexec module</h3>
        <input id="netexec-module" placeholder="module (e.g. smb)" />
        <input id="netexec-target" placeholder="target host" />
        <input id="netexec-flags" placeholder="extra flags (optional)" />
        <button onclick="enumNetexec()">Run Netexec</button>

        <h3>SMB Shares (smbclient/smbmap)</h3>
        <input id="smbshares-host" placeholder="host or IP" />
        <input id="smbshares-user" placeholder="username (optional)" />
        <input id="smbshares-pass" placeholder="password (optional)" type="password" />
        <input id="smbshares-domain" placeholder="domain (optional)" />
        <input id="smbshares-tool" placeholder="tool (smbclient|smbmap, optional)" />
        <button onclick="enumSMBShares()">Enum SMB Shares</button>
      </div>

      <div class="card">
        <h2>Beacon generation</h2>

        <h3>Havoc</h3>
        <input id="havoc-args" placeholder="havoc client args (e.g. --windows-demon ...)" style="width:100%" />
        <button onclick="beaconHavoc()">Generate Havoc beacon</button>

        <h3>Empire (raw JSON config)</h3>
        <textarea id="empire-config" style="height:120px;" placeholder='{"listener_type":"http", "listener_name":"rustygo-http", "stager_type":"multi/launcher"}'></textarea>
        <button onclick="beaconEmpire()">Generate Empire stager</button>

        <h3>Adaptix (raw JSON config)</h3>
        <textarea id="adaptix-config" style="height:120px;" placeholder='{"listener":"http", "format":"exe", "profile":"default"}'></textarea>
        <button onclick="beaconAdaptix()">Generate Adaptix agent</button>
      </div>
    </div>

    <div class="col">
      <div class="card">
        <h2>Jobs</h2>
        <button onclick="loadJobs()">Refresh Jobs</button>
        <table id="jobs">
          <thead><tr><th>ID</th><th>Domain</th><th>Status</th><th>Progress</th><th>Actions</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="card">
        <h2>Saved results</h2>
        <button onclick="loadResults()">Refresh</button>
        <table id="results">
          <thead><tr><th>File</th><th>Actions</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="card">
        <h2>Directory / LDAP & BloodHound</h2>
        <h3>ldapsearch</h3>
        <input id="ldap-host" placeholder="ldap.example.com:389" />
        <input id="ldap-basedn" placeholder="DC=example,DC=com" />
        <input id="ldap-filter" placeholder="(objectClass=user)" />
        <input id="ldap-attrs" placeholder="cn,sAMAccountName,memberOf (optional)" />
        <input id="ldap-binddn" placeholder="bind DN (optional)" />
        <input id="ldap-password" type="password" placeholder="password (optional)" />
        <label><input type="checkbox" id="ldap-use-ldaps" /> use LDAPS</label>
        <button onclick="runLDAP()">Run ldapsearch</button>

        <h3>BloodHound JSON summary</h3>
        <textarea id="bh-json" style="height:80px;" placeholder="Paste BloodHound JSON with nodes/edges here"></textarea>
        <button onclick="bloodhoundSummary()">Summarize BloodHound JSON</button>
      </div>

      <div class="card">
        <h2>Host profile & privesc hints</h2>
        <p>Paste a HostProfile JSON from an agent or C2 and analyze for privesc hints.</p>
        <textarea id="host-profile-json" style="width:100%;height:120px;" placeholder='{"hostname":"dc01","os_family":"windows","os_version":"10.0","local_users":[...],...}'></textarea>
        <button onclick="analyzeHostProfile()">Analyze host profile</button>
      </div>

      <div class="card">
        <h2>AD Graph visualization</h2>
        <p>Paste BloodHound JSON and render a simplified relationship graph. High-value nodes are highlighted.</p>
        <textarea id="bh-json-graph" style="width:100%;height:120px;" placeholder="Paste BloodHound JSON with nodes/edges here"></textarea>
        <button onclick="renderBHGraph()">Render AD graph</button>
        <div id="graph-container" style="margin-top:8px; border:1px solid #1f2937; border-radius:8px; padding:4px; max-height:400px; overflow:auto;">
          <svg id="graph-svg" width="600" height="400"></svg>
        </div>
      </div>

      <div class="card">
        <h2>Summary</h2>
        <div id="summary">Run a recon or load a result to see a summary here.</div>
      </div>

      <div class="card">
        <h2>Raw JSON</h2>
        <pre id="preview" style="white-space:pre-wrap; max-height:400px; overflow:auto;"></pre>
      </div>
    </div>
  </div>

<script>
async function runSync() {
  const domain = document.getElementById('domain').value.trim();
  if (!domain) return;
  document.getElementById('status').textContent = 'Running...';
  const res = await fetch('/api/run/full', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain })
  });
  if (!res.ok) {
    document.getElementById('status').textContent = 'Error';
    const text = await res.text();
    document.getElementById('preview').textContent = text;
    document.getElementById('summary').innerHTML = '';
    return;
  }
  const data = await res.json();
  document.getElementById('status').textContent = 'Done';
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  renderSummary(data);
  loadResults();
}

async function startJob() {
  const domain = document.getElementById('async-domain').value.trim();
  if (!domain) return;
  document.getElementById('async-status').textContent = 'Queued...';
  const res = await fetch('/api/jobs/full', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain })
  });
  if (!res.ok) {
    document.getElementById('async-status').textContent = 'Error';
    const text = await res.text();
    document.getElementById('preview').textContent = text;
    return;
  }
  const data = await res.json();
  document.getElementById('async-status').textContent = 'Job ' + data.id;
  loadJobs();
}

async function loadJobs() {
  const res = await fetch('/api/jobs');
  if (!res.ok) return;
  const data = await res.json();
  const tbody = document.querySelector('#jobs tbody');
  tbody.innerHTML = '';
  data.forEach(job => {
    const tr = document.createElement('tr');
    const idTd = document.createElement('td');
    idTd.textContent = job.id;
    const domainTd = document.createElement('td');
    domainTd.textContent = job.domain;
    const statusTd = document.createElement('td');
    statusTd.textContent = job.status + (job.stage ? ' (' + job.stage + ')' : '');
    const progressTd = document.createElement('td');
    progressTd.textContent = job.progress + '%';
    const actionsTd = document.createElement('td');
    const btn = document.createElement('button');
    btn.textContent = 'View';
    btn.onclick = () => viewJob(job.id);
    actionsTd.appendChild(btn);

    tr.appendChild(idTd);
    tr.appendChild(domainTd);
    tr.appendChild(statusTd);
    tr.appendChild(progressTd);
    tr.appendChild(actionsTd);
    tbody.appendChild(tr);
  });
}

async function viewJob(id) {
  const res = await fetch('/api/jobs/' + encodeURIComponent(id));
  if (!res.ok) return;
  const job = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(job, null, 2);
  renderSummary(job);
}

// Saved results
async function loadResults() {
  const res = await fetch('/api/results');
  if (!res.ok) return;
  const data = await res.json();
  const tbody = document.querySelector('#results tbody');
  tbody.innerHTML = '';
  data.forEach(item => {
    const tr = document.createElement('tr');
    const nameTd = document.createElement('td');
    nameTd.textContent = item.file;
    const actionsTd = document.createElement('td');
    const btn = document.createElement('button');
    btn.textContent = 'View';
    btn.onclick = () => loadResult(item.file);
    actionsTd.appendChild(btn);
    tr.appendChild(nameTd);
    tr.appendChild(actionsTd);
    tbody.appendChild(tr);
  });
}

async function loadResult(name) {
  const res = await fetch('/api/results/' + encodeURIComponent(name));
  if (!res.ok) return;
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  renderSummary(data);
}

// Enumeration helpers
async function enumSMB() {
  const host = document.getElementById('smb-host').value.trim();
  const opts = document.getElementById('smb-opts').value.trim();
  if (!host) return;
  const res = await fetch('/api/enum/smb', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host, opts })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  document.getElementById('summary').innerHTML = '<p><strong>enum4linux-ng host:</strong> ' + data.host + '</p>';
}

async function enumNetBIOS() {
  const ip = document.getElementById('netbios-ip').value.trim();
  if (!ip) return;
  const res = await fetch('/api/enum/netbios', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  let html = '<p><strong>NetBIOS IP:</strong> ' + data.ip + '</p>';
  if (data.workgroup) html += '<p><strong>Workgroup:</strong> ' + data.workgroup + '</p>';
  if (data.names && data.names.length) {
    html += '<p><strong>Names:</strong></p><ul>';
    data.names.forEach(n => {
      html += '<li>' + n.name + ' &lt;' + n.suffix + '&gt; (' + n.type + ')</li>';
    });
    html += '</ul>';
  }
  document.getElementById('summary').innerHTML = html;
}

async function enumNetexec() {
  const module = document.getElementById('netexec-module').value.trim();
  const target = document.getElementById('netexec-target').value.trim();
  const flags = document.getElementById('netexec-flags').value.trim();
  if (!module || !target) return;
  const res = await fetch('/api/enum/netexec', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ module, target, flags })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  let html = '<p><strong>Netexec module:</strong> ' + data.module + '</p>';
  html += '<p><strong>Target:</strong> ' + data.host + '</p>';
  document.getElementById('summary').innerHTML = html;
}

async function enumSMBShares() {
  const host = document.getElementById('smbshares-host').value.trim();
  const username = document.getElementById('smbshares-user').value.trim();
  const password = document.getElementById('smbshares-pass').value.trim();
  const domain = document.getElementById('smbshares-domain').value.trim();
  const tool = document.getElementById('smbshares-tool').value.trim();
  if (!host) return;
  const res = await fetch('/api/enum/smbshares', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host, username, password, domain, tool })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);

  let html = '<p><strong>SMB shares on:</strong> ' + data.host + ' (tool: ' + data.tool + ')</p>';
  if (data.shares && data.shares.length) {
    html += '<table><thead><tr><th>Share</th><th>Comment</th><th>R</th><th>W</th></tr></thead><tbody>';
    data.shares.forEach(sh => {
      html += '<tr><td>' + sh.name + '</td><td>' + (sh.comment || '') + '</td><td>' +
              (sh.read ? '✔' : '') + '</td><td>' + (sh.write ? '✔' : '') + '</td></tr>';
    });
    html += '</tbody></table>';
  } else if (data.raw_output) {
    html += '<p>No parsed shares; see raw output.</p>';
  }
  document.getElementById('summary').innerHTML = html;
}

// Beacon helpers
async function beaconHavoc() {
  const args = document.getElementById('havoc-args').value.trim();
  const res = await fetch('/api/beacon/havoc', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ args })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  document.getElementById('summary').innerHTML = '<p>Havoc beacon command output.</p>';
}

async function beaconEmpire() {
  const raw = document.getElementById('empire-config').value.trim();
  if (!raw) return;
  let cfg;
  try { cfg = JSON.parse(raw); } catch (e) {
    alert('Empire config is not valid JSON');
    return;
  }
  const res = await fetch('/api/beacon/empire', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg)
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  document.getElementById('summary').innerHTML =
    '<p><strong>Empire listener:</strong> ' + (data.listener || '') + '</p>';
}

async function beaconAdaptix() {
  const raw = document.getElementById('adaptix-config').value.trim();
  if (!raw) return;
  let cfg;
  try { cfg = JSON.parse(raw); } catch (e) {
    alert('Adaptix config is not valid JSON');
    return;
  }
  const res = await fetch('/api/beacon/adaptix', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ config: cfg })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  document.getElementById('summary').innerHTML =
    '<p><strong>Adaptix agent ID:</strong> ' + (data.id || '') +
    '<br/><strong>Download URL:</strong> ' + (data.url || '') + '</p>';
}

// LDAP & BloodHound helpers
async function runLDAP() {
  const host = document.getElementById('ldap-host').value.trim();
  const base_dn = document.getElementById('ldap-basedn').value.trim();
  const filter = document.getElementById('ldap-filter').value.trim();
  const attrs = document.getElementById('ldap-attrs').value.trim();
  const bind_dn = document.getElementById('ldap-binddn').value.trim();
  const password = document.getElementById('ldap-password').value.trim();
  const use_ldaps = document.getElementById('ldap-use-ldaps').checked;
  if (!host || !base_dn) return;
  const res = await fetch('/api/ad/ldap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host, base_dn, filter, attrs, bind_dn, password, use_ldaps })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);

  let html = '<p><strong>LDAP host:</strong> ' + data.host + '</p>';
  html += '<p><strong>Base DN:</strong> ' + data.base_dn + '</p>';
  html += '<p><strong>Filter:</strong> ' + data.filter + '</p>';
  html += '<p><strong>Entries:</strong> ' + data.count + '</p>';
  document.getElementById('summary').innerHTML = html;
}

async function bloodhoundSummary() {
  const raw = document.getElementById('bh-json').value.trim();
  if (!raw) return;
  const res = await fetch('/api/ad/bloodhound/summary', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ json: raw })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);

  let html = '<p><strong>BloodHound summary:</strong> ' +
             data.node_count + ' nodes, ' + data.edge_count + ' edges</p>';
  if (data.node_types) {
    html += '<p><strong>Node types:</strong></p><ul>';
    for (const t in data.node_types) {
      html += '<li>' + t + ': ' + data.node_types[t] + '</li>';
    }
    html += '</ul>';
  }
  document.getElementById('summary').innerHTML = html;
}

// Host profile & privesc
async function analyzeHostProfile() {
  const raw = document.getElementById('host-profile-json').value.trim();
  if (!raw) return;
  let profile;
  try {
    profile = JSON.parse(raw);
  } catch (e) {
    alert('HostProfile is not valid JSON');
    return;
  }
  const res = await fetch('/api/host/profile/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);

  let html = '<p><strong>Host:</strong> ' + (data.profile.hostname || '') +
             ' (' + (data.profile.os_family || '') + ' ' + (data.profile.os_version || '') + ')</p>';
  if (data.hints && data.hints.length) {
    html += '<p><strong>Privesc hints:</strong> ' + data.hints.length + '</p><ul>';
    data.hints.forEach(h => {
      html += '<li><strong>[' + h.severity.toUpperCase() + '][' + h.category + ']</strong> ' +
              h.title + '<br/><span style="opacity:0.8;">' + h.description + '</span></li>';
    });
    html += '</ul>';
  } else {
    html += '<p>No privesc hints found by current heuristics.</p>';
  }
  document.getElementById('summary').innerHTML = html;
}

// AD graph visualization
async function renderBHGraph() {
  const raw = document.getElementById('bh-json-graph').value.trim();
  if (!raw) return;
  const res = await fetch('/api/ad/bloodhound/graph', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ json: raw })
  });
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);

  drawGraph(data);
}

function drawGraph(graph) {
  const svg = document.getElementById('graph-svg');
  const width = svg.clientWidth || 600;
  const height = svg.clientHeight || 400;
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  if (!graph || !graph.nodes || !graph.nodes.length) {
    return;
  }

  const nodes = graph.nodes;
  const edges = graph.edges || [];
  const cx = width / 2, cy = height / 2;
  const radius = Math.min(width, height) / 2 - 40;

  // Position nodes on a circle
  nodes.forEach((n, i) => {
    const angle = 2 * Math.PI * i / nodes.length;
    n._x = cx + radius * Math.cos(angle);
    n._y = cy + radius * Math.sin(angle);
  });

  // Draw edges
  edges.forEach(e => {
    const src = nodes.find(n => n.id === e.source);
    const dst = nodes.find(n => n.id === e.target);
    if (!src || !dst) return;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", src._x);
    line.setAttribute("y1", src._y);
    line.setAttribute("x2", dst._x);
    line.setAttribute("y2", dst._y);
    line.setAttribute("stroke", "#4b5563");
    line.setAttribute("stroke-width", "1");
    svg.appendChild(line);
  });

  // Draw nodes
  nodes.forEach(n => {
    const group = document.createElementNS("http://www.w3.org/2000/svg", "g");

    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", n._x);
    circle.setAttribute("cy", n._y);
    circle.setAttribute("r", 10);
    circle.setAttribute("fill", n.high_value ? "#f97316" : "#1d4ed8");
    group.appendChild(circle);

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", n._x + 12);
    text.setAttribute("y", n._y + 4);
    text.setAttribute("font-size", "10");
    text.setAttribute("fill", "#e5e7eb");
    text.textContent = n.name || n.label || n.id;
    group.appendChild(text);

    svg.appendChild(group);
  });

  // Update summary
  let html = '<p><strong>AD graph:</strong> ' + nodes.length + ' nodes, ' +
             edges.length + ' edges.</p>';
  const hv = nodes.filter(n => n.high_value);
  if (hv.length) {
    html += '<p><strong>High-value nodes:</strong></p><ul>';
    hv.forEach(n => {
      html += '<li>' + (n.name || n.id) + ' [' + (n.label || '') + ']</li>';
    });
    html += '</ul>';
  }
  document.getElementById('summary').innerHTML = html;
}

// Summary renderer for ReconResult or Job{result}
function renderSummary(obj) {
  let res = obj;
  if (obj && obj.result && obj.result.domain) {
    res = obj.result;
  }
  if (!res || !res.domain) {
    return;
  }
  const subs = res.subdomains || [];
  const dns = res.dns || [];
  const ports = res.ports || [];
  const http = res.http || [];
  const vulns = res.vulns || [];

  let html = '';
  html += '<p><strong>Domain:</strong> ' + res.domain + '</p>';
  html += '<p><strong>Subdomains:</strong> ' + subs.length +
          ' | <strong>DNS records:</strong> ' + dns.length +
          ' | <strong>Ports:</strong> ' + ports.length +
          ' | <strong>HTTP services:</strong> ' + http.length +
          ' | <strong>Vulns:</strong> ' + vulns.length + '</p>';

  if (subs.length) {
    html += '<p><strong>Top subdomains:</strong></p><ul>';
    subs.slice(0, 5).forEach(s => {
      html += '<li>' + s.name + ' <span style="opacity:0.7;">(' + (s.source || 'unknown') + ')</span></li>';
    });
    html += '</ul>';
  }

  if (ports.length) {
    html += '<p><strong>Sample open ports:</strong></p><ul>';
    ports.slice(0, 5).forEach(p => {
      html += '<li>' + p.host + ':' + p.port + ' ' + p.protocol +
              (p.service ? ' [' + p.service + ']' : '') + '</li>';
    });
    html += '</ul>';
  }

  if (http.length) {
    html += '<p><strong>Sample HTTP services:</strong></p><ul>';
    http.slice(0, 5).forEach(h => {
      html += '<li>' + h.url + ' [' + h.status_code + '] ' +
              (h.title ? ' - ' + h.title : '') + '</li>';
    });
    html += '</ul>';
  }

  if (vulns.length) {
    html += '<p><strong>Sample findings:</strong></p><ul>';
    vulns.slice(0, 5).forEach(v => {
      html += '<li>' + (v.severity || 'unknown').toUpperCase() +
              ' - ' + (v.id || v.template || 'unknown') +
              ' @ ' + (v.target || '') + '</li>';
    });
    html += '</ul>';
  }

  document.getElementById('summary').innerHTML = html;
}

loadJobs();
loadResults();
</script>
</body>
</html>`
