package authsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// IntrospectionResponse models an RFC 7662 response extended with OIDC-ish
// fields that AuthSec returns.
type IntrospectionResponse struct {
	Active    bool        `json:"active"`
	Scope     string      `json:"scope,omitempty"`
	ClientID  string      `json:"client_id,omitempty"`
	Username  string      `json:"username,omitempty"`
	TokenType string      `json:"token_type,omitempty"`
	Exp       int64       `json:"exp,omitempty"`
	Iat       int64       `json:"iat,omitempty"`
	Nbf       int64       `json:"nbf,omitempty"`
	Sub       string      `json:"sub,omitempty"`
	Aud       interface{} `json:"aud,omitempty"` // string or []string per RFC 7662
	Iss       string      `json:"iss,omitempty"`
	Jti       string      `json:"jti,omitempty"`
	ContextID string      `json:"context_id,omitempty"` // AuthSec-specific
}

// Scopes returns the parsed scope list.
func (r *IntrospectionResponse) Scopes() []string {
	if r.Scope == "" {
		return nil
	}
	return strings.Fields(r.Scope)
}

// Audiences returns the audience as a []string regardless of wire form.
func (r *IntrospectionResponse) Audiences() []string {
	if r.Aud == nil {
		return nil
	}
	switch v := r.Aud.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// HasAudience reports whether the given resource_uri is in the audience list.
func (r *IntrospectionResponse) HasAudience(resourceURI string) bool {
	for _, a := range r.Audiences() {
		if a == resourceURI {
			return true
		}
	}
	return false
}

// Introspector calls the AuthSec introspection endpoint.
type Introspector struct {
	cfg    *Config
	client *http.Client

	mu    sync.Mutex
	cache map[string]cachedResult
}

type cachedResult struct {
	resp      *IntrospectionResponse
	expiresAt time.Time
}

// NewIntrospector returns an Introspector. Call Config.Validate first.
func NewIntrospector(cfg *Config) *Introspector {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Introspector{
		cfg:    cfg,
		client: client,
		cache:  make(map[string]cachedResult),
	}
}

// Introspect validates token with AuthSec. Returns (resp, nil) when the call
// succeeded — the caller must still check resp.Active.
func (i *Introspector) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	if token == "" {
		return nil, fmt.Errorf("authsec: empty token")
	}

	if r, ok := i.cacheGet(token); ok {
		return r, nil
	}

	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		i.cfg.IntrospectionEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("authsec: build introspect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(i.cfg.ResourceServerID, i.cfg.IntrospectionSecret)

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authsec: introspect: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authsec: introspect status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ir IntrospectionResponse
	if err := json.Unmarshal(body, &ir); err != nil {
		return nil, fmt.Errorf("authsec: decode introspect response: %w", err)
	}

	if ir.Active {
		i.cachePut(token, &ir)
	}
	return &ir, nil
}

func (i *Introspector) cacheGet(token string) (*IntrospectionResponse, bool) {
	if i.cfg.CacheTTL <= 0 {
		return nil, false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	c, ok := i.cache[token]
	if !ok || time.Now().After(c.expiresAt) {
		if ok {
			delete(i.cache, token)
		}
		return nil, false
	}
	return c.resp, true
}

func (i *Introspector) cachePut(token string, resp *IntrospectionResponse) {
	ttl := i.cfg.CacheTTL
	if ttl <= 0 {
		return
	}
	// Clamp to token's own exp when shorter.
	if resp.Exp > 0 {
		remaining := time.Until(time.Unix(resp.Exp, 0))
		if remaining > 0 && remaining < ttl {
			ttl = remaining
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cache[token] = cachedResult{resp: resp, expiresAt: time.Now().Add(ttl)}
}
