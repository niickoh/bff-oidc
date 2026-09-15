package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	SessionCookieName  = "bff_session"
	StateCookieName    = "bff_oidc_state"
	NonceCookieName    = "bff_oidc_nonce"
	VerifierCookieName = "bff_oidc_verifier"
)

type Config struct {
	AppAddr          string
	AppBaseURL       string
	FrontendURL      string
	OIDCIssuer       string
	OIDCAuthURL      string
	OIDCTokenURL     string
	OIDCUserInfoURL  string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCScopes       []string
	SessionSecret    []byte
	CookieDomain     string
	CookieSecure     bool
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		AppAddr:          getenv("APP_ADDR", ":8080"),
		AppBaseURL:       os.Getenv("APP_BASE_URL"),
		FrontendURL:      os.Getenv("FRONTEND_URL"),
		OIDCIssuer:       os.Getenv("OIDC_ISSUER"),
		OIDCAuthURL:      os.Getenv("OIDC_AUTH_URL"),
		OIDCTokenURL:     os.Getenv("OIDC_TOKEN_URL"),
		OIDCUserInfoURL:  os.Getenv("OIDC_USERINFO_URL"),
		OIDCClientID:     os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
		OIDCScopes:       splitScopes(getenv("OIDC_SCOPES", "openid profile email offline_access")),
		SessionSecret:    []byte(os.Getenv("SESSION_SECRET")),
		CookieDomain:     os.Getenv("COOKIE_DOMAIN"),
	}

	secure, err := parseBoolEnv("COOKIE_SECURE", true)
	if err != nil {
		return Config{}, err
	}
	cfg.CookieSecure = secure

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	required := map[string]string{
		"APP_BASE_URL":       c.AppBaseURL,
		"FRONTEND_URL":       c.FrontendURL,
		"OIDC_ISSUER":        c.OIDCIssuer,
		"OIDC_AUTH_URL":      c.OIDCAuthURL,
		"OIDC_TOKEN_URL":     c.OIDCTokenURL,
		"OIDC_USERINFO_URL":  c.OIDCUserInfoURL,
		"OIDC_CLIENT_ID":     c.OIDCClientID,
		"OIDC_CLIENT_SECRET": c.OIDCClientSecret,
		"OIDC_REDIRECT_URL":  c.OIDCRedirectURL,
		"SESSION_SECRET":     string(c.SessionSecret),
		"COOKIE_DOMAIN":      c.CookieDomain,
	}

	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	if len(c.SessionSecret) < 32 {
		return fmt.Errorf("SESSION_SECRET must be at least 32 bytes")
	}

	for _, raw := range []string{c.AppBaseURL, c.FrontendURL, c.OIDCIssuer, c.OIDCAuthURL, c.OIDCTokenURL, c.OIDCUserInfoURL, c.OIDCRedirectURL} {
		if err := validateSecureURL(raw); err != nil {
			return err
		}
	}

	if !c.CookieSecure {
		return fmt.Errorf("COOKIE_SECURE must be true")
	}

	return nil
}

func (c Config) FrontendDashboardURL() string {
	return strings.TrimRight(c.FrontendURL, "/") + "/dashboard"
}

func getenv(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func splitScopes(raw string) []string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return []string{"openid", "profile", "email", "offline_access"}
	}
	return fields
}

func parseBoolEnv(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", name)
	}
}

func validateSecureURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	return fmt.Errorf("URL %q must use https", raw)
}
