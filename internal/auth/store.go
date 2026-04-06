// Package auth manages OAuth 2.0 PKCE authentication and token lifecycle.
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/saucesteals/ccproxy/internal/safejson"
)

const stateFile = "state.json"

// Identity holds the authenticated user's identity.
type Identity struct {
	DeviceID    string `json:"deviceID"`
	Email       string `json:"email"`
	AccountUUID string `json:"accountUUID"`
}

// SessionID returns a stable per-process session identifier.
func (s *Store) SessionID() string {
	return s.sessionID
}

// Tokens holds the current OAuth token set.
type Tokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"`
}

// state is the single persisted file.
type state struct {
	Tokens   Tokens   `json:"tokens"`
	Identity Identity `json:"identity"`
}

// Store owns identity and OAuth 2.0 PKCE tokens.
type Store struct {
	configDir  string
	userAgent  string
	httpClient *http.Client

	mu    sync.RWMutex
	state state

	// PKCE auth flow state.
	authMu          sync.Mutex
	pendingVerifier string
	pendingState    string
	authTimer       *time.Timer

	// Refresh loop lifecycle.
	cancelRefresh context.CancelFunc
	sessionID     string
}

// NewStore creates a new auth store.
func NewStore(configDir, version string) *Store {
	return &Store{
		configDir:  configDir,
		userAgent:  fmt.Sprintf("claude-cli/%s (external, cli)", version),
		httpClient: http.DefaultClient,
		sessionID:  randomHex(16),
	}
}

// Load reads persisted state from disk.
func (s *Store) Load() error {
	data, err := os.ReadFile(filepath.Join(s.configDir, stateFile))
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}

	var st state
	if err := safejson.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse state: %w", err)
	}

	s.mu.Lock()
	s.state = st
	s.mu.Unlock()

	slog.Info("auth loaded",
		"email", st.Identity.Email,
		"expires", time.UnixMilli(st.Tokens.ExpiresAt).Format(time.RFC3339),
	)

	return nil
}

// save persists current tokens and identity to disk.
func (s *Store) save() error {
	s.mu.RLock()
	st := s.state
	s.mu.RUnlock()

	data, err := safejson.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.MkdirAll(s.configDir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(s.configDir, stateFile), data, 0600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}

	return nil
}

// Identity returns the current identity.
func (s *Store) Identity() Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.state.Identity
}

// AccessToken returns the current OAuth access token.
func (s *Store) AccessToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.state.Tokens.AccessToken
}

// Logout clears all tokens and identity, persists the empty state.
func (s *Store) Logout() {
	if s.cancelRefresh != nil {
		s.cancelRefresh()
	}

	s.mu.Lock()
	s.state = state{}
	s.mu.Unlock()

	if err := s.save(); err != nil {
		slog.Warn("failed to persist logout", "error", err)
	}

	slog.Info("logged out")
}
