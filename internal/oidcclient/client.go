package oidcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/niickoh/bff-oidc/internal/config"
	"golang.org/x/oauth2"
)

type Client struct {
	httpClient  *http.Client
	oauthConfig oauth2.Config
	verifier    *oidc.IDTokenVerifier
	userInfoURL string
	clientID    string
	clientSecret string
	tokenURL    string
}

type AuthResult struct {
	Sub          string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Profile      map[string]any
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

type idTokenClaims struct {
	Sub               string `json:"sub"`
	Nonce             string `json:"nonce"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
}

func New(ctx context.Context, cfg config.Config) (*Client, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		oauthConfig: oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  cfg.OIDCRedirectURL,
			Scopes:       cfg.OIDCScopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   cfg.OIDCAuthURL,
				TokenURL:  cfg.OIDCTokenURL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID}),
		userInfoURL:  cfg.OIDCUserInfoURL,
		clientID:     cfg.OIDCClientID,
		clientSecret: cfg.OIDCClientSecret,
		tokenURL:     cfg.OIDCTokenURL,
	}, nil
}

func (c *Client) AuthorizationURL(state, nonce, codeChallenge string) string {
	return c.oauthConfig.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier, expectedNonce string) (AuthResult, error) {
	token, err := c.oauthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return AuthResult{}, fmt.Errorf("exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return AuthResult{}, fmt.Errorf("token response missing id_token")
	}

	claims, err := c.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		return AuthResult{}, err
	}
	if claims.Nonce != expectedNonce {
		return AuthResult{}, fmt.Errorf("invalid nonce")
	}

	profile, err := c.userInfo(ctx, token.AccessToken)
	if err != nil {
		profile = map[string]any{}
	}
	mergeClaims(profile, claims)

	return AuthResult{
		Sub:          claims.Sub,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    expiryOrDefault(token.Expiry),
		Profile:      profile,
	}, nil
}

func (c *Client) Refresh(ctx context.Context, refreshToken, expectedSub string) (AuthResult, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return AuthResult{}, fmt.Errorf("create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return AuthResult{}, fmt.Errorf("refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AuthResult{}, fmt.Errorf("refresh token: unexpected status %d", resp.StatusCode)
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return AuthResult{}, fmt.Errorf("decode refresh response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return AuthResult{}, fmt.Errorf("refresh response missing access_token")
	}

	result := AuthResult{
		Sub:          expectedSub,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: firstNonEmpty(tokenResp.RefreshToken, refreshToken),
		ExpiresAt:    expiryFromSeconds(tokenResp.ExpiresIn),
	}

	if tokenResp.IDToken != "" {
		claims, err := c.verifyIDToken(ctx, tokenResp.IDToken)
		if err != nil {
			return AuthResult{}, err
		}
		if expectedSub != "" && claims.Sub != expectedSub {
			return AuthResult{}, fmt.Errorf("refresh subject mismatch")
		}
		result.Sub = claims.Sub
		result.Profile = map[string]any{}
		mergeClaims(result.Profile, claims)
	}

	profile, err := c.userInfo(ctx, result.AccessToken)
	if err == nil {
		if result.Profile == nil {
			result.Profile = map[string]any{}
		}
		for key, value := range profile {
			result.Profile[key] = value
		}
	}

	return result, nil
}

func (c *Client) verifyIDToken(ctx context.Context, raw string) (idTokenClaims, error) {
	token, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("verify id_token: %w", err)
	}

	var claims idTokenClaims
	if err := token.Claims(&claims); err != nil {
		return idTokenClaims{}, fmt.Errorf("decode id_token claims: %w", err)
	}
	return claims, nil
}

func (c *Client) userInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo request: unexpected status %d", resp.StatusCode)
	}

	var profile map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return profile, nil
}

func mergeClaims(profile map[string]any, claims idTokenClaims) {
	profile["sub"] = claims.Sub
	if claims.Name != "" {
		profile["name"] = claims.Name
	}
	if claims.PreferredUsername != "" {
		profile["preferred_username"] = claims.PreferredUsername
	}
	if claims.Email != "" {
		profile["email"] = claims.Email
		profile["email_verified"] = claims.EmailVerified
	}
}

func expiryOrDefault(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().Add(time.Hour)
	}
	return value
}

func expiryFromSeconds(seconds int64) time.Time {
	if seconds <= 0 {
		return time.Now().Add(time.Hour)
	}
	return time.Now().Add(time.Duration(seconds) * time.Second)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
