package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/saucesteals/ccproxy/internal/safejson"
)

const (
	tokenURL    = "https://platform.claude.com/v1/oauth/token"
	profileURL  = "https://api.anthropic.com/api/oauth/profile"
	clientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	oauthScopes = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
)

// StartAuth generates a PKCE challenge and returns the OAuth authorization URL.
func (s *Store) StartAuth() (string, error) {
	s.authMu.Lock()
	defer s.authMu.Unlock()

	s.clearPendingAuthLocked()

	verifier, err := generateCodeVerifier()
	if err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}

	challenge := generateCodeChallenge(verifier)

	st, err := generateState()
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	s.pendingVerifier = verifier
	s.pendingState = st
	s.authTimer = time.AfterFunc(2*time.Minute, func() {
		slog.Info("auth session timed out")
		s.authMu.Lock()
		s.clearPendingAuthLocked()
		s.authMu.Unlock()
	})

	params := url.Values{}
	params.Set("code", "true")
	params.Set("client_id", clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", oauthScopes)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", st)

	return authorizeURL + "?" + params.Encode(), nil
}

// CompleteAuth exchanges the authorization code for tokens and fetches the user profile.
func (s *Store) CompleteAuth(code, authState string) error {
	s.authMu.Lock()
	if s.pendingState == "" || s.pendingState != authState {
		s.authMu.Unlock()

		return fmt.Errorf("invalid or expired auth state")
	}
	verifier := s.pendingVerifier
	s.clearPendingAuthLocked()
	s.authMu.Unlock()

	tokens, err := s.exchangeCode(code, verifier, authState)
	if err != nil {
		return err
	}

	identity, err := s.fetchProfile(tokens.AccessToken)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.state = state{
		Tokens:   tokens,
		Identity: identity,
	}
	s.mu.Unlock()

	if err := s.save(); err != nil {
		slog.Warn("failed to persist state after auth", "error", err)
	}

	s.StartRefreshLoop()

	return nil
}

// StartRefreshLoop cancels any existing refresh loop and starts a new one.
func (s *Store) StartRefreshLoop() {
	s.mu.Lock()
	if s.cancelRefresh != nil {
		s.cancelRefresh()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelRefresh = cancel
	s.mu.Unlock()

	go s.refreshLoop(ctx)
}

func (s *Store) refreshLoop(ctx context.Context) {
	for {
		s.mu.RLock()
		expiresAt := s.state.Tokens.ExpiresAt
		s.mu.RUnlock()

		ttl := time.Until(time.UnixMilli(expiresAt)) - 5*time.Minute
		if ttl > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(ttl):
			}
		}

		s.mu.RLock()
		refreshTok := s.state.Tokens.RefreshToken
		s.mu.RUnlock()

		tokens, err := s.refreshToken(refreshTok)
		if err != nil {
			slog.Error("oauth refresh failed, retrying in 30s", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}

			continue
		}

		s.mu.Lock()
		s.state.Tokens = tokens
		s.mu.Unlock()

		if err := s.save(); err != nil {
			slog.Warn("failed to persist state after refresh", "error", err)
		}

		slog.Info("oauth refreshed",
			"expires", time.UnixMilli(tokens.ExpiresAt).Format(time.RFC3339),
		)
	}
}

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	State        string `json:"state,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (s *Store) exchangeCode(code, verifier, authState string) (Tokens, error) {
	return s.postToken(tokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  redirectURI,
		ClientID:     clientID,
		CodeVerifier: verifier,
		State:        authState,
	})
}

func (s *Store) refreshToken(refreshTok string) (Tokens, error) {
	return s.postToken(tokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshTok,
		ClientID:     clientID,
		Scope:        oauthScopes,
	})
}

func (s *Store) postToken(body tokenRequest) (Tokens, error) {
	payload, err := safejson.Marshal(body)
	if err != nil {
		return Tokens{}, fmt.Errorf("marshal token request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewReader(payload))
	if err != nil {
		return Tokens{}, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return Tokens{}, fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return Tokens{}, fmt.Errorf("token request %d: %s", resp.StatusCode, respBody)
	}

	var result tokenResponse
	if err := safejson.Unmarshal(respBody, &result); err != nil {
		return Tokens{}, fmt.Errorf("parse token response: %w", err)
	}

	now := time.Now().UnixMilli()

	return Tokens{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    now + result.ExpiresIn*1000,
	}, nil
}

type profileResponse struct {
	Account struct {
		UUID  string `json:"uuid"`
		Email string `json:"email"`
	} `json:"account"`
}

func (s *Store) fetchProfile(accessToken string) (Identity, error) {
	req, err := http.NewRequest(http.MethodGet, profileURL, nil)
	if err != nil {
		return Identity{}, fmt.Errorf("create profile request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("fetch profile: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("fetch profile %d: %s", resp.StatusCode, body)
	}

	var profile profileResponse
	if err := safejson.Unmarshal(body, &profile); err != nil {
		return Identity{}, fmt.Errorf("parse profile: %w", err)
	}

	return Identity{
		DeviceID:    randomHex(32),
		Email:       profile.Account.Email,
		AccountUUID: profile.Account.UUID,
	}, nil
}

func (s *Store) clearPendingAuthLocked() {
	if s.authTimer != nil {
		s.authTimer.Stop()
		s.authTimer = nil
	}
	s.pendingVerifier = ""
	s.pendingState = ""
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}
