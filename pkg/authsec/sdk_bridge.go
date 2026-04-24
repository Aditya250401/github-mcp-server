package authsec

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	authsecsdk "github.com/authsec-ai/sdk-authsec/packages/go-sdk"
	ghcontext "github.com/github/github-mcp-server/pkg/context"
	ghutils "github.com/github/github-mcp-server/pkg/utils"
)

// SDKConfig translates the local GitHub MCP AuthSec settings into the generic
// AuthSec Go SDK configuration. This keeps the existing operator-facing flags
// stable while making the SDK the canonical MCP protection layer.
func (c *Config) SDKConfig(logger *slog.Logger) authsecsdk.Config {
	issuer := strings.TrimRight(c.Issuer, "/")
	policyMode := authsecsdk.PolicyModeRemoteRequired
	if c.ToolScopes != nil {
		policyMode = authsecsdk.PolicyModeRemoteWithLocalFallback
	}

	return authsecsdk.Config{
		Issuer:                    issuer,
		AuthorizationServer:       issuer,
		JWKSURL:                   issuer + "/oauth/jwks",
		IntrospectionURL:          c.IntrospectionEndpoint(),
		IntrospectionClientID:     c.ResourceServerID,
		IntrospectionClientSecret: c.IntrospectionSecret,
		ResourceURI:               c.ResourceURI,
		ResourceName:              "GitHub MCP Server",
		ResourceServerID:          c.ResourceServerID,
		SupportedScopes:           append([]string(nil), c.RequiredScopes...),
		ToolScopes:                authsecsdk.ToolScopeMap(c.ToolScopes),
		ScopeMatrixTTL:            c.CacheTTL,
		PolicyMode:                policyMode,
		ValidationMode:            authsecsdk.ValidationModeJWTAndIntrospect,
		HTTPClient:                c.HTTPClient,
		Logger:                    logger,
	}
}

// NewSDKRuntime creates the canonical AuthSec SDK runtime for GitHub MCP
// Server HTTP mode.
func NewSDKRuntime(cfg *Config, logger *slog.Logger) (*authsecsdk.Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return authsecsdk.NewRuntime(cfg.SDKConfig(logger))
}

// BridgeToGitHubContext adapts the validated AuthSec SDK principal into the
// request context shapes that github-mcp-server already consumes.
func BridgeToGitHubContext(next http.Handler, cfg *Config, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := authsecsdk.PrincipalFromContext(r.Context())
		if !ok || principal == nil {
			http.Error(w, "validated principal missing from AuthSec SDK context", http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		ctx = ghcontext.WithPrincipal(ctx, &ghcontext.Principal{
			Subject: principal.Subject,
			Issuer:  principal.Issuer,
			Scopes:  append([]string(nil), principal.Scopes...),
			Claims:  principal.Claims,
		})
		ctx = ghcontext.WithUpstreamToken(ctx, &ghcontext.UpstreamToken{
			Token:  cfg.UpstreamGitHubToken,
			Source: "authsec-sdk",
		})
		// TokenInfo is still used by existing middleware as the "auth already
		// handled" sentinel. Keep the token type as unknown so PAT scope fetch
		// logic does not re-run against the upstream GitHub credential.
		ctx = ghcontext.WithTokenInfo(ctx, &ghcontext.TokenInfo{
			Token:     cfg.UpstreamGitHubToken,
			TokenType: ghutils.TokenTypeUnknown,
		})
		ctx = ghcontext.WithTokenScopes(ctx, append([]string(nil), principal.Scopes...))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MetadataPath returns the exact RFC 9728 metadata path that the SDK will own
// for this resource.
func (c *Config) MetadataPath() (string, error) {
	if err := c.Validate(); err != nil {
		return "", fmt.Errorf("invalid authsec config: %w", err)
	}
	return authsecsdk.BuildResourceMetadataPath(c.ResourceURI), nil
}
