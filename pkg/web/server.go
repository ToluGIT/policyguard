// Package web serves the PolicyGuard GUI: a small Go HTTP server that accepts
// uploaded or pasted Terraform/OpenTofu, runs the real scan pipeline in-process,
// and renders the same terminal-mono dashboard the static HTML reporter produces.
//
// Security posture (the server is a tool that parses untrusted IaC):
//   - Binds to localhost by default; --public must be explicit to expose it.
//   - Only the trusted embedded policy set is ever loaded — a web request can
//     never point the engine at an arbitrary --policy directory (that would let
//     a remote caller run untrusted Rego). The OPA capability sandbox still
//     applies on top.
//   - Uploads are written to a per-request temp dir under the OS temp root, with
//     sanitized base filenames (no path traversal), a total-size cap, an
//     allowed-extension allowlist, and a request timeout. The temp dir is
//     removed after each scan.
//   - A simple per-client rate limit blunts abuse in --public mode.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ToluGIT/policyguard/pkg/analyzer"
	"github.com/ToluGIT/policyguard/pkg/logger"
	"github.com/ToluGIT/policyguard/pkg/parser/terraform"
	"github.com/ToluGIT/policyguard/pkg/policy/opa"
	"github.com/ToluGIT/policyguard/pkg/remediation"
	htmlreporter "github.com/ToluGIT/policyguard/pkg/reporter/html"
	"github.com/ToluGIT/policyguard/pkg/types"
)

//go:embed assets/index.html assets/guide.html assets/gui.js assets/favicon.svg assets/favicon-32.png assets/apple-touch-icon.png
var guiAssets embed.FS

// Config controls server behavior.
type Config struct {
	Addr    string // listen address, e.g. "127.0.0.1:8080"
	Public  bool   // hardened public mode (upload-only, stricter limits)
	Version string // build version, surfaced in the UI
}

// Limits are the request safety bounds. Public mode tightens them.
type Limits struct {
	MaxUploadBytes int64
	MaxFiles       int
	ScanTimeout    time.Duration
}

func limitsFor(public bool) Limits {
	if public {
		return Limits{MaxUploadBytes: 1 << 20, MaxFiles: 25, ScanTimeout: 15 * time.Second} // 1 MiB
	}
	return Limits{MaxUploadBytes: 16 << 20, MaxFiles: 200, ScanTimeout: 60 * time.Second} // 16 MiB
}

// allowedExt is the set of extensions the GUI will scan. Anything else is
// rejected before it ever touches the parser.
var allowedExt = map[string]bool{
	".tf": true, ".tofu": true, ".json": true, ".hcl": true,
}

// Server holds the running GUI state.
type Server struct {
	cfg    Config
	limits Limits
	tmpl   *template.Template

	rl *rateLimiter
}

// New constructs a Server with parsed templates.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	tmpl, err := template.New("gui").ParseFS(guiAssets, "assets/index.html", "assets/guide.html")
	if err != nil {
		return nil, fmt.Errorf("parse gui templates: %w", err)
	}
	return &Server{
		cfg:    cfg,
		limits: limitsFor(cfg.Public),
		tmpl:   tmpl,
		rl:     newRateLimiter(30, time.Minute),
	}, nil
}

// Handler returns the configured HTTP mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/guide", s.handleGuide)
	mux.HandleFunc("/assets/dashboard.css", s.handleReporterAsset("assets/dashboard.css", "text/css; charset=utf-8"))
	mux.HandleFunc("/assets/dashboard.js", s.handleReporterAsset("assets/dashboard.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/assets/gui.js", s.handleGUIAsset("assets/gui.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/assets/favicon.svg", s.handleGUIAsset("assets/favicon.svg", "image/svg+xml"))
	mux.HandleFunc("/assets/favicon-32.png", s.handleGUIAsset("assets/favicon-32.png", "image/png"))
	mux.HandleFunc("/assets/apple-touch-icon.png", s.handleGUIAsset("assets/apple-touch-icon.png", "image/png"))
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/scan", s.handleScan)
	return securityHeaders(mux)
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Bound the whole request read (slow-loris / trickle-body upload) and
		// idle keep-alives, not just the headers. WriteTimeout is generous
		// enough to render a large report.
		ReadTimeout:  s.limits.ScanTimeout + 30*time.Second,
		WriteTimeout: s.limits.ScanTimeout + 30*time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return srv.ListenAndServe()
}

// --- handlers ---------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	css, _ := htmlreporter.Assets().ReadFile("assets/dashboard.css")
	data := struct {
		Version string
		Public  bool
		CSS     template.CSS
		MaxMB   int64
		MaxFile int
	}{
		Version: s.cfg.Version,
		Public:  s.cfg.Public,
		CSS:     template.CSS(css),
		MaxMB:   s.limits.MaxUploadBytes >> 20,
		MaxFile: s.limits.MaxFiles,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// handleGuide serves the static usage guide.
func (s *Server) handleGuide(w http.ResponseWriter, r *http.Request) {
	css, _ := htmlreporter.Assets().ReadFile("assets/dashboard.css")
	data := struct {
		Version string
		Public  bool
		CSS     template.CSS
		MaxMB   int64
		MaxFile int
	}{
		Version: s.cfg.Version,
		Public:  s.cfg.Public,
		CSS:     template.CSS(css),
		MaxMB:   s.limits.MaxUploadBytes >> 20,
		MaxFile: s.limits.MaxFiles,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "guide.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Server) handleReporterAsset(name, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := htmlreporter.Assets().ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(b)
	}
}

func (s *Server) handleGUIAsset(name, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := guiAssets.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(b)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","version":%q,"public":%t}`, s.cfg.Version, s.cfg.Public)
}

// handleScan accepts a multipart upload (files) and/or a pasted-HCL form field,
// writes them to a temp dir, runs the scan, and returns the rendered dashboard
// body fragment.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.rl.allow(clientKey(r)) {
		http.Error(w, "rate limit exceeded — try again shortly", http.StatusTooManyRequests)
		return
	}

	// Cap the whole request body before parsing.
	r.Body = http.MaxBytesReader(w, r.Body, s.limits.MaxUploadBytes)
	if err := r.ParseMultipartForm(s.limits.MaxUploadBytes); err != nil {
		http.Error(w, "request too large or malformed", http.StatusBadRequest)
		return
	}
	// ParseMultipartForm spills parts above the in-memory threshold to temp files
	// on disk; those are cleaned up only by RemoveAll on the parsed form.
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	dir, err := os.MkdirTemp("", "policyguard-gui-*")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(dir)

	written, err := s.materialize(r, dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if written == 0 {
		http.Error(w, "no Terraform/OpenTofu content provided", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.limits.ScanTimeout)
	defer cancel()

	report, err := s.scan(ctx, dir)
	if err != nil {
		// Log the detailed error (which can include server filesystem paths)
		// server-side only; return a generic message to the client so the
		// response can't disclose the host's directory layout.
		logger.Default().Warn("scan failed: %v", err)
		http.Error(w, "scan failed: the configuration could not be analyzed (it may be invalid Terraform/OpenTofu)", http.StatusUnprocessableEntity)
		return
	}

	// Rewrite the temp dir out of file paths so the UI shows clean names, not
	// the server's filesystem layout. Evidence is still read from disk by
	// joining the temp dir back on (RenderBody's sourceRoot), so the UI shows
	// "main.tf" while evidence reads from <tempdir>/main.tf.
	rebaseReportPaths(report, dir)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := htmlreporter.RenderBody(report, s.cfg.Version, dir, w); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// rebaseReportPaths strips the temp-scan-dir prefix from every file path in the
// report so the UI displays clean, relative names instead of the server's
// filesystem layout.
func rebaseReportPaths(report *types.Report, dir string) {
	trim := func(p string) string {
		if rel, err := filepath.Rel(dir, p); err == nil && !strings.HasPrefix(rel, "..") {
			return rel
		}
		return filepath.Base(p)
	}
	for i := range report.Violations {
		report.Violations[i].Location.File = trim(report.Violations[i].Location.File)
	}
	for i := range report.Resources {
		report.Resources[i].Location.File = trim(report.Resources[i].Location.File)
	}
}

// materialize writes uploaded files + pasted HCL into dir, enforcing the
// file-count cap, extension allowlist, and sanitized base names. Returns the
// number of files written.
func (s *Server) materialize(r *http.Request, dir string) (int, error) {
	written := 0

	// Pasted HCL (a single textarea field).
	if pasted := strings.TrimSpace(r.FormValue("content")); pasted != "" {
		if err := os.WriteFile(filepath.Join(dir, "pasted.tf"), []byte(pasted), 0o600); err != nil {
			return written, fmt.Errorf("write pasted content")
		}
		written++
	}

	if r.MultipartForm != nil {
		for _, fh := range r.MultipartForm.File["files"] {
			if written >= s.limits.MaxFiles {
				return written, fmt.Errorf("too many files (max %d)", s.limits.MaxFiles)
			}
			name := sanitizeName(fh.Filename)
			if name == "" {
				continue
			}
			if !allowedExt[strings.ToLower(filepath.Ext(name))] {
				return written, fmt.Errorf("unsupported file type %q (allowed: .tf, .tofu, .tf.json, .hcl)", filepath.Ext(name))
			}
			if err := saveUpload(fh, filepath.Join(dir, name)); err != nil {
				return written, fmt.Errorf("save %s: %v", name, err)
			}
			written++
		}
	}
	return written, nil
}

// scan runs the real pipeline against dir using ONLY the embedded policy set.
func (s *Server) scan(ctx context.Context, dir string) (*types.Report, error) {
	log := logger.Default()
	log.SetLevel(logger.ErrorLevel)

	p := terraform.New()
	p.WithLogger(log)
	// Confine module resolution to the upload dir: uploaded Terraform must not be
	// able to follow a `../../` module source into host-local directories.
	p.WithConfinedRoot(dir)

	engine := opa.New()
	// Always the embedded, trusted policies — never a request-controlled dir.
	if err := engine.LoadEmbeddedPolicies(ctx); err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	a := analyzer.New(p, engine, remediation.NewBasicSuggester(), htmlreporter.New())
	return a.AnalyzePaths(ctx, []string{dir})
}

// --- helpers ----------------------------------------------------------------

func saveUpload(fh *multipart.FileHeader, dst string) error {
	src, err := fh.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

// sanitizeName reduces an uploaded filename to a safe base name (defeats path
// traversal like "../../etc/x" and absolute paths).
func sanitizeName(name string) string {
	name = filepath.Base(filepath.FromSlash(name))
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return ""
	}
	// Drop any character that isn't a safe filename rune.
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// The page only loads its own same-origin assets and an inline style.
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func clientKey(r *http.Request) string {
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// rateLimiter is a tiny fixed-window per-client limiter.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: map[string][]time.Time{}, limit: limit, window: window}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.limit {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)

	// Opportunistically prune fully-expired clients so the map doesn't grow
	// without bound as distinct IPs come and go (matters in --public mode).
	if len(rl.hits) > 1024 {
		for k, ts := range rl.hits {
			if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
				delete(rl.hits, k)
			}
		}
	}
	return true
}
