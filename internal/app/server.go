package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/niickoh/bff-oidc/internal/config"
	"github.com/niickoh/bff-oidc/internal/oidcclient"
	"github.com/niickoh/bff-oidc/internal/session"
)

const (
	authFlowCookieTTL = 10 * time.Minute
	rateLimitWindow   = time.Minute
	rateLimitMaxHits  = 10
)

type Server struct {
	cfg        config.Config
	oidc       *oidcclient.Client
	sessions   *session.Store
	loginLimit *rateLimiter
	cbLimit    *rateLimiter
}

type rateLimiter struct {
	mu      sync.Mutex
	hits    map[string]rateState
	limit   int
	window  time.Duration
	nowFunc func() time.Time
}

type rateState struct {
	count   int
	expires time.Time
}

func NewServer(cfg config.Config, oidc *oidcclient.Client, sessions *session.Store) *Server {
	return &Server{
		cfg:        cfg,
		oidc:       oidc,
		sessions:   sessions,
		loginLimit: newRateLimiter(rateLimitMaxHits, rateLimitWindow),
		cbLimit:    newRateLimiter(rateLimitMaxHits, rateLimitWindow),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("GET /auth/me", s.withSession(s.handleMe))
	mux.HandleFunc("POST /auth/refresh", s.withSession(s.handleRefresh))
	mux.HandleFunc("POST /auth/logout", s.withSession(s.handleLogout))
	return s.requireHTTPS(s.cors(mux))
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if !s.loginLimit.Allow(clientIP(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	verifier, err := randomToken(64)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}

	if err := s.setSignedCookie(w, config.StateCookieName, state, authFlowCookieTTL, true); err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	if err := s.setSignedCookie(w, config.NonceCookieName, nonce, authFlowCookieTTL, true); err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	if err := s.setSignedCookie(w, config.VerifierCookieName, verifier, authFlowCookieTTL, true); err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, s.oidc.AuthorizationURL(state, nonce, pkceChallenge(verifier)), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if !s.cbLimit.Allow(clientIP(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	s.clearAuthFlowCookies(w)

	expectedState, err := s.readSignedCookie(r, config.StateCookieName)
	if err != nil {
		http.Error(w, "missing login state", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(expectedState), []byte(state)) != 1 {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	nonce, err := s.readSignedCookie(r, config.NonceCookieName)
	if err != nil {
		http.Error(w, "missing login nonce", http.StatusBadRequest)
		return
	}
	verifier, err := s.readSignedCookie(r, config.VerifierCookieName)
	if err != nil {
		http.Error(w, "missing code verifier", http.StatusBadRequest)
		return
	}

	authResult, err := s.oidc.ExchangeCode(r.Context(), code, verifier, nonce)
	if err != nil {
		http.Error(w, "oidc callback failed", http.StatusBadGateway)
		return
	}

	sessionID, err := randomToken(32)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}

	s.sessions.Put(session.Session{
		ID:           sessionID,
		Sub:          authResult.Sub,
		AccessToken:  authResult.AccessToken,
		RefreshToken: authResult.RefreshToken,
		ExpiresAt:    authResult.ExpiresAt,
		Profile:      authResult.Profile,
	})

	if err := s.setSignedCookie(w, config.SessionCookieName, sessionID, 0, true); err != nil {
		http.Error(w, "could not persist session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, s.cfg.FrontendDashboardURL(), http.StatusFound)
}

func (s *Server) handleMe(w http.ResponseWriter, _ *http.Request, current session.Session) {
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request, current session.Session) {
	if current.RefreshToken == "" {
		http.Error(w, "session cannot be refreshed", http.StatusBadRequest)
		return
	}

	refreshed, err := s.oidc.Refresh(r.Context(), current.RefreshToken, current.Sub)
	if err != nil {
		http.Error(w, "refresh failed", http.StatusBadGateway)
		return
	}

	if refreshed.Profile == nil {
		refreshed.Profile = current.Profile
	}

	current.AccessToken = refreshed.AccessToken
	current.RefreshToken = refreshed.RefreshToken
	current.ExpiresAt = refreshed.ExpiresAt
	current.Profile = refreshed.Profile
	current.Sub = firstNonEmpty(refreshed.Sub, current.Sub)
	s.sessions.Put(current)

	writeJSON(w, http.StatusOK, current)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, _ session.Session) {
	if sessionID, err := s.readSignedCookie(r, config.SessionCookieName); err == nil {
		s.sessions.Delete(sessionID)
	}
	s.clearCookie(w, config.SessionCookieName, true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) withSession(next func(http.ResponseWriter, *http.Request, session.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		sessionID, err := s.readSignedCookie(r, config.SessionCookieName)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		current, ok := s.sessions.Get(sessionID)
		if !ok {
			s.clearCookie(w, config.SessionCookieName, true)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r, current)
	}
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && origin == s.cfg.FrontendURL {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}

		if r.Method == http.MethodOptions {
			if origin != s.cfg.FrontendURL {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireHTTPS(next http.Handler) http.Handler {
	if s.cfg.AllowsInsecureHTTP() {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "https required", http.StatusUpgradeRequired)
	})
}

func (s *Server) setSignedCookie(w http.ResponseWriter, name, value string, maxAge time.Duration, httpOnly bool) error {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(value))
	sig := s.sign(name + "." + encoded)
	cookie := &http.Cookie{
		Name:     name,
		Value:    encoded + "." + sig,
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		HttpOnly: httpOnly,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}

	if maxAge > 0 {
		cookie.MaxAge = int(maxAge.Seconds())
		cookie.Expires = time.Now().Add(maxAge)
	}

	http.SetCookie(w, cookie)
	return nil
}

func (s *Server) readSignedCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return "", errors.New("invalid cookie format")
	}

	expectedSig := s.sign(name + "." + parts[0])
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedSig)) != 1 {
		return "", errors.New("invalid cookie signature")
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode cookie: %w", err)
	}
	return string(raw), nil
}

func (s *Server) clearAuthFlowCookies(w http.ResponseWriter) {
	s.clearCookie(w, config.StateCookieName, true)
	s.clearCookie(w, config.NonceCookieName, true)
	s.clearCookie(w, config.VerifierCookieName, true)
}

func (s *Server) clearCookie(w http.ResponseWriter, name string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: httpOnly,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) sign(value string) string {
	mac := hmac.New(sha256.New, s.cfg.SessionSecret)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		hits:    make(map[string]rateState),
		limit:   limit,
		window:  window,
		nowFunc: time.Now,
	}
}

func (r *rateLimiter) Allow(key string) bool {
	if key == "" {
		key = "unknown"
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowFunc()
	state, ok := r.hits[key]
	if !ok || now.After(state.expires) {
		r.hits[key] = rateState{
			count:   1,
			expires: now.Add(r.window),
		}
		return true
	}
	if state.count >= r.limit {
		return false
	}

	state.count++
	r.hits[key] = state
	return true
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
