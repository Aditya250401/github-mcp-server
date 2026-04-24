package authsec

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config configures the AuthSec integration for the GitHub MCP server.
type Config struct {
	// Issuer is the AuthSec base URL (e.g. https://authsec.example).
	// Advertised as the authorization_server in OAuth Protected Resource Metadata.
	Issuer string

	// ResourceURI is the audience this RS expects on AuthSec-issued tokens
	// (RFC 8707). Must equal the resource_uri of the RS record in AuthSec.
	ResourceURI string

	// ResourceServerID is the UUID of this RS in AuthSec. Used as the Basic-auth
	// username when calling the introspection endpoint.
	ResourceServerID string

	// IntrospectionSecret is the sec_* secret issued by AuthSec when the RS was
	// created. Used as the Basic-auth password for introspection.
	IntrospectionSecret string

	// IntrospectionURL overrides the default of Issuer + "/oauth/introspect".
	IntrospectionURL string

	// UpstreamGitHubToken is the GitHub PAT / App token used to call
	// api.github.com after the AuthSec bearer has been validated. The AuthSec
	// access token is never forwarded to GitHub.
	UpstreamGitHubToken string

	// RequiredScopes, if non-empty, requires the introspected token to carry at
	// least one of these scopes. Leave empty to disable scope enforcement here
	// (fine-grained enforcement belongs inside tool handlers).
	RequiredScopes []string

	// ToolScopes carries the local inventory-derived MCP tool policy used to
	// bootstrap the generic AuthSec SDK when the remote scope matrix is not yet
	// available. This is populated by HTTP mode at runtime; operators do not set
	// it directly.
	ToolScopes map[string][]string

	// HTTPClient is used for introspection. Defaults to a client with a 10s
	// timeout when nil.
	HTTPClient *http.Client

	// CacheTTL is how long active introspection results are cached per token.
	// Defaults to 60s. Set to 0 to disable caching.
	CacheTTL time.Duration
}

// Enabled returns true when AuthSec is configured.
func (c *Config) Enabled() bool {
	return c != nil &&
		c.Issuer != "" &&
		c.ResourceURI != "" &&
		c.ResourceServerID != "" &&
		c.IntrospectionSecret != "" &&
		c.UpstreamGitHubToken != ""
}

// Validate returns an error describing the first missing required field.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("authsec config is nil")
	}
	missing := []string{}
	if c.Issuer == "" {
		missing = append(missing, "issuer")
	}
	if c.ResourceURI == "" {
		missing = append(missing, "resource_uri")
	}
	if c.ResourceServerID == "" {
		missing = append(missing, "resource_server_id")
	}
	if c.IntrospectionSecret == "" {
		missing = append(missing, "introspection_secret")
	}
	if c.UpstreamGitHubToken == "" {
		missing = append(missing, "upstream_github_token")
	}
	if len(missing) > 0 {
		return fmt.Errorf("authsec config missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

// IntrospectionEndpoint returns the effective introspection URL.
func (c *Config) IntrospectionEndpoint() string {
	if c.IntrospectionURL != "" {
		return c.IntrospectionURL
	}
	return strings.TrimSuffix(c.Issuer, "/") + "/oauth/introspect"
}

// ConfigFromEnv loads AuthSec configuration from environment variables.
// Returns (nil, nil) when no AuthSec vars are set at all — lets the caller
// keep the default GitHub PAT flow. Returns (cfg, err) if vars are partially
// set.
func ConfigFromEnv() (*Config, error) {
	issuer := os.Getenv("AUTHSEC_ISSUER")
	resourceURI := os.Getenv("AUTHSEC_RESOURCE_URI")
	rsID := os.Getenv("AUTHSEC_RESOURCE_SERVER_ID")
	secret := os.Getenv("AUTHSEC_INTROSPECTION_SECRET")
	upstream := os.Getenv("AUTHSEC_UPSTREAM_GITHUB_TOKEN")
	if upstream == "" {
		upstream = os.Getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
	}

	// All empty → AuthSec not configured, bail silently.
	if issuer == "" && resourceURI == "" && rsID == "" && secret == "" {
		return nil, nil
	}

	cfg := &Config{
		Issuer:              issuer,
		ResourceURI:         resourceURI,
		ResourceServerID:    rsID,
		IntrospectionSecret: secret,
		IntrospectionURL:    os.Getenv("AUTHSEC_INTROSPECTION_URL"),
		UpstreamGitHubToken: upstream,
	}
	if scopes := os.Getenv("AUTHSEC_REQUIRED_SCOPES"); scopes != "" {
		cfg.RequiredScopes = splitAndTrim(scopes, ",")
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
