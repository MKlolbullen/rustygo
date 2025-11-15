package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/MKlolbullen/rustygo/internal/config"
	"github.com/MKlolbullen/rustygo/internal/model"
	"github.com/MKlolbullen/rustygo/internal/pipeline"
)

type Server struct {
	cfg    *config.Config
	mux    *http.ServeMux
	dataDir string
}

func New(cfg *config.Config, dataDir string) *Server {
	mux := http.NewServeMux()
	s := &Server{cfg: cfg, mux: mux, dataDir: dataDir}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/run/full", s.handleRunFull)
	s.mux.HandleFunc("/api/results", s.handleListResults)
	s.mux.HandleFunc("/api/results/", s.handleGetResult)
	s.mux.HandleFunc("/", s.handleIndex)
}

func (s *Server) ListenAndServe(addr string) error {
	log.Printf("rustygo GUI listening on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

// Launch full pipeline (blocking for now; later make async job queue)
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
	res, err := p.Run(ctx, pipeline.FullOptions{Domain: body.Domain})
	if err != nil {
		http.Error(w, fmt.Sprintf("pipeline error: %v", err), http.StatusInternalServerError)
		return
	}

	if err := s.saveResult(res); err != nil {
		log.Printf("save result error: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

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
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
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
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleGetResult(w http.ResponseWriter, r *http.Request) {
	// /api/results/<filename>
	name := r.URL.Path[len("/api/results/"):]
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.dataDir, name)
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, f)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

const indexHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>rustygo GUI</title>
  <style>
    body { font-family: system-ui, sans-serif; background:#0b1120; color:#e5e7eb; margin:0; padding:20px; }
    h1 { margin-bottom: 0.5rem; }
    .card { background:#020617; border:1px solid #1f2937; border-radius:12px; padding:16px; margin-bottom:16px; }
    input, button { padding:8px; border-radius:8px; border:1px solid #4b5563; background:#020617; color:#e5e7eb; }
    button { cursor:pointer; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; background:#111827; font-size:12px; margin-right:4px; }
    table { width:100%; border-collapse:collapse; font-size:14px; }
    th, td { padding:6px 8px; border-bottom:1px solid #1f2937; }
    tr:hover { background:#020617; }
  </style>
</head>
<body>
  <h1>rustygo</h1>
  <p>Multi-phase recon pipeline with Go + Rust, wrapped in a simple UI.</p>

  <div class="card">
    <h2>Run full recon</h2>
    <input id="domain" placeholder="example.com" />
    <button onclick="runRecon()">Run</button>
    <span id="status" class="pill"></span>
  </div>

  <div class="card">
    <h2>Previous results</h2>
    <button onclick="loadResults()">Refresh</button>
    <table id="results">
      <thead><tr><th>File</th><th>Actions</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card">
    <h2>Result preview</h2>
    <pre id="preview" style="white-space:pre-wrap; max-height:400px; overflow:auto;"></pre>
  </div>

<script>
async function runRecon() {
  const domain = document.getElementById('domain').value.trim();
  if (!domain) return;
  document.getElementById('status').textContent = 'Running...';
  const res = await fetch('/api/run/full', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain })
  });
  const data = await res.json();
  document.getElementById('status').textContent = 'Done';
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
  loadResults();
}

async function loadResults() {
  const res = await fetch('/api/results');
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
  const data = await res.json();
  document.getElementById('preview').textContent = JSON.stringify(data, null, 2);
}

loadResults();
</script>
</body>
</html>`
