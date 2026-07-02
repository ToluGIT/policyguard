package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T, public bool) http.Handler {
	t.Helper()
	s, err := New(Config{Addr: "127.0.0.1:0", Public: public, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.Handler()
}

func multipartScan(t *testing.T, fields map[string]string, files map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	for name, content := range files {
		fw, err := w.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte(content))
	}
	_ = w.Close()
	return &buf, w.FormDataContentType()
}

func TestIndexServes(t *testing.T) {
	h := newTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "PolicyGuard") {
		t.Error("index missing wordmark")
	}
	// Security headers present.
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing CSP header")
	}
}

func TestScanPastedContent(t *testing.T) {
	h := newTestServer(t, false)
	body, ctype := multipartScan(t,
		map[string]string{"content": "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n  acl = \"public-read-write\"\n}\n"},
		nil)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d, body=%s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, "s3_bucket_public_access") {
		t.Error("expected the real public-access finding in the rendered fragment")
	}
	if !strings.Contains(out, `class="row"`) {
		t.Error("expected dashboard rows in the fragment")
	}
}

func TestScanUploadedFile(t *testing.T) {
	h := newTestServer(t, false)
	body, ctype := multipartScan(t, nil, map[string]string{
		"main.tf": "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n  acl = \"public-read\"\n}\n",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload scan status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `class="row"`) {
		t.Error("expected findings from uploaded file")
	}
}

func TestRejectUnsupportedExtension(t *testing.T) {
	h := newTestServer(t, false)
	body, ctype := multipartScan(t, nil, map[string]string{"secrets.txt": "nope"})
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for .txt upload, got %d", rec.Code)
	}
}

func TestEmptyScanRejected(t *testing.T) {
	h := newTestServer(t, false)
	body, ctype := multipartScan(t, map[string]string{"content": "   "}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty content, got %d", rec.Code)
	}
}

// TestModuleSourceTraversalConfined verifies the server's confinement: an
// uploaded config whose module source points outside the sandbox (../../...) is
// not followed, so it cannot make the server read host-local directories. The
// scan still succeeds on the in-sandbox content.
func TestModuleSourceTraversalConfined(t *testing.T) {
	h := newTestServer(t, true) // public mode — the boundary that must hold
	body, ctype := multipartScan(t, map[string]string{
		"content": "module \"escape\" {\n  source = \"../../../../../../etc\"\n}\nresource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n  acl = \"public-read\"\n}\n",
	}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("scan status = %d, body=%s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	// The in-sandbox bucket is still flagged...
	if !strings.Contains(out, "s3_bucket_public_access") {
		t.Error("expected the in-sandbox S3 finding")
	}
	// ...and nothing from outside the sandbox leaked in (no absolute host paths).
	if strings.Contains(out, "/etc/") {
		t.Error("a host path outside the sandbox leaked into the report")
	}
}

// TestScanErrorIsGeneric verifies scan errors don't echo server filesystem
// paths back to the client.
func TestScanErrorIsGeneric(t *testing.T) {
	h := newTestServer(t, false)
	// Invalid HCL that should fail to parse.
	body, ctype := multipartScan(t, map[string]string{"content": "this is not valid terraform {{{"}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Whatever the status, the body must not contain an absolute server path.
	if strings.Contains(rec.Body.String(), "/var/") || strings.Contains(rec.Body.String(), "/tmp/") || strings.Contains(rec.Body.String(), os.TempDir()) {
		t.Errorf("error response leaked a server path: %q", rec.Body.String())
	}
}

func TestGetScanNotAllowed(t *testing.T) {
	h := newTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/scan", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /api/scan, got %d", rec.Code)
	}
}

func TestSanitizeNameDefeatsTraversal(t *testing.T) {
	cases := map[string]string{
		"../../../etc/passwd.tf": "etc_passwd.tf", // .. stripped to base, then sanitized
		"/abs/path/main.tf":      "main.tf",
		"weird name!.tf":         "weird_name_.tf",
		"..":                     "",
		"":                       "",
	}
	for in, want := range cases {
		// filepath.Base("../../../etc/passwd.tf") = "passwd.tf"; assert no separators survive.
		got := sanitizeName(in)
		if strings.ContainsAny(got, "/\\") {
			t.Errorf("sanitizeName(%q)=%q still contains a path separator", in, got)
		}
		// For the empty/.. cases we require empty out.
		if want == "" && got != "" {
			t.Errorf("sanitizeName(%q)=%q, want empty", in, got)
		}
	}
	// A traversal name must reduce to its base file, never escape.
	if got := sanitizeName("../../etc/passwd.tf"); got != "passwd.tf" {
		t.Errorf("sanitizeName traversal = %q, want passwd.tf", got)
	}
}

// TestScanEscapesMaliciousContent locks in that a crafted .tf cannot inject
// active markup into the rendered fragment (it is assigned via innerHTML on the
// client, so unescaped <img onerror> would execute).
func TestScanEscapesMaliciousContent(t *testing.T) {
	h := newTestServer(t, false)
	body, ctype := multipartScan(t, map[string]string{
		"content": "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"<img src=x onerror=alert(1)>\"\n  acl = \"public-read\"\n}\n",
	}, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Header.Set("Content-Type", ctype)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := rec.Body.String()
	if strings.Contains(out, "<img src=x onerror=alert(1)>") {
		t.Error("malicious markup rendered unescaped — XSS via innerHTML")
	}
}

func TestRateLimiterPrunes(t *testing.T) {
	rl := newRateLimiter(5, time.Hour)
	// Fill past the prune threshold with distinct, immediately-stale clients.
	for i := 0; i < 1100; i++ {
		rl.hits["client-"+itoaTest(i)] = nil // empty slice => prunable
	}
	// One live request triggers the opportunistic prune.
	rl.allow("live")
	if len(rl.hits) > 1024 {
		t.Errorf("rate-limiter map not pruned: %d entries", len(rl.hits))
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(2, time.Hour)
	if !rl.allow("a") || !rl.allow("a") {
		t.Fatal("first two requests should be allowed")
	}
	if rl.allow("a") {
		t.Error("third request should be rate-limited")
	}
	if !rl.allow("b") {
		t.Error("a different client should not be limited")
	}
}
