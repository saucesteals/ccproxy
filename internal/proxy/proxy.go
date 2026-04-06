package proxy

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/saucesteals/ccproxy/internal/auth"
	"github.com/saucesteals/ccproxy/internal/safejson"
)

var betaHeaders = []string{
	"oauth-2025-04-20",
	"interleaved-thinking-2025-05-14",
	"redact-thinking-2026-02-12",
	"context-management-2025-06-27",
	"prompt-caching-scope-2026-01-05",
	"structured-outputs-2025-12-15",
	"token-efficient-tools-2026-03-28",
	"fast-mode-2026-02-01",
	"effort-2025-11-24",
	"web-search-2025-03-05",
	"advanced-tool-use-2025-11-20",
}

type Config struct {
	AuthToken string
	Upstream  string
	Version   string
	Auth      *auth.Store
}

type Handler struct {
	token    string
	upstream string
	version  string
	client   *http.Client
	auth     *auth.Store
}

func New(cfg Config) *Handler {
	return &Handler{
		token:    cfg.AuthToken,
		upstream: cfg.Upstream,
		version:  cfg.Version,
		client:   http.DefaultClient,
		auth:     cfg.Auth,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	slog.Info("request", "method", r.Method, "path", path)

	if path == "/_health" {
		h.serveHealth(w)
		return
	}

	if !h.authenticate(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	switch {
	case path == "/_auth":
		h.serveAuth(w, r)
	case strings.Contains(path, "/event_logging/"):
		writeJSON(w, http.StatusOK, struct{}{})
	default:
		h.serveProxy(w, r)
	}
}

func (h *Handler) authenticate(r *http.Request) bool {
	if h.token == "" {
		return true
	}
	return subtle.ConstantTimeCompare(
		[]byte(r.Header.Get("x-api-key")),
		[]byte(h.token),
	) == 1
}

func (h *Handler) serveAuth(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if h.auth.AccessToken() != "" {
			id := h.auth.Identity()
			writeJSON(w, http.StatusOK, map[string]any{
				"status": "authenticated",
				"email":  id.Email,
			})
			return
		}
		authURL, err := h.auth.StartAuth()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"url": authURL})

	case http.MethodPost:
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		parts := strings.SplitN(strings.TrimSpace(string(raw)), "#", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			writeError(w, http.StatusBadRequest, "body must be code#state")
			return
		}
		if err := h.auth.CompleteAuth(parts[0], parts[1]); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case http.MethodDelete:
		if err := h.auth.Logout(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) serveHealth(w http.ResponseWriter) {
	status, code := "ok", http.StatusOK
	if h.auth.AccessToken() == "" {
		status, code = "needs_auth", http.StatusServiceUnavailable
	}

	writeJSON(w, code, map[string]any{
		"status":   status,
		"upstream": h.upstream,
		"version":  h.version,
	})
}

func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request) {
	if h.auth.AccessToken() == "" {
		writeError(w, http.StatusServiceUnavailable, "no oauth token — run auth first")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	rewritten, hash := body, "000"
	if strings.HasPrefix(r.URL.Path, "/v1/messages") {
		var err error
		rewritten, hash, err = h.rewriteMessages(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to rewrite request: "+err.Error())
			return
		}
	}

	upstreamURL := h.buildUpstreamURL(r)
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(rewritten))
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to create upstream request")
		return
	}
	req.Header = h.buildHeaders(r.Header, hash)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))

	resp, err := h.client.Do(req)
	if err != nil {
		slog.Error("upstream error", "error", err)
		writeError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	h.streamResponse(w, resp)
	slog.Info("response", "status", resp.StatusCode, "path", r.URL.Path)
}

func (h *Handler) buildUpstreamURL(r *http.Request) string {
	u, _ := url.Parse(h.upstream)
	u.Path = r.URL.Path
	u.RawQuery = r.URL.RawQuery

	if strings.HasPrefix(r.URL.Path, "/v1/messages") && !u.Query().Has("beta") {
		q := u.Query()
		q.Set("beta", "true")
		u.RawQuery = q.Encode()
	}

	return u.String()
}

func (h *Handler) buildHeaders(orig http.Header, hash string) http.Header {
	hdrs := http.Header{}

	if ct := orig.Get("Content-Type"); ct != "" {
		hdrs.Set("Content-Type", ct)
	}

	hdrs.Set("Authorization", "Bearer "+h.auth.AccessToken())
	hdrs.Set("User-Agent", fmt.Sprintf("claude-cli/%s (external, cli)", h.version))
	hdrs.Set("x-app", "cli")
	hdrs.Set("anthropic-version", "2023-06-01")
	hdrs.Set("anthropic-dangerous-direct-browser-access", "true")
	hdrs.Set("anthropic-beta", strings.Join(betaHeaders, ","))
	hdrs.Set("x-anthropic-billing-header", fmt.Sprintf("cc_version=%s.%s; cc_entrypoint=cli;", h.version, hash))
	hdrs.Set("x-stainless-lang", "js")
	hdrs.Set("x-stainless-runtime", "node")
	hdrs.Set("x-stainless-runtime-version", "v25.6.1")
	hdrs.Set("x-stainless-arch", "arm64")
	hdrs.Set("x-stainless-os", "MacOS")
	hdrs.Set("x-stainless-package-version", "0.80.0")
	hdrs.Set("x-stainless-retry-count", "0")
	hdrs.Set("x-stainless-timeout", "600")

	return hdrs
}

func (h *Handler) streamResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	f, canFlush := w.(http.Flusher)
	if !canFlush {
		body, _ := io.ReadAll(resp.Body)
		_, _ = w.Write(unprefixResponse(body, resp.Header.Get("Content-Type")))
		return
	}

	stripper := newToolStripper()
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if out := stripper.Write(buf[:n]); len(out) > 0 {
				_, _ = w.Write(out)
				f.Flush()
			}
		}
		if err != nil {
			if out := stripper.Flush(); len(out) > 0 {
				_, _ = w.Write(out)
				f.Flush()
			}
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	data, _ := safejson.Marshal(v)
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n"))
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
