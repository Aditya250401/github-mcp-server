package authsec

import (
	"fmt"
	"log/slog"
	"net/http"

	ghcontext "github.com/github/github-mcp-server/pkg/context"
	"github.com/github/github-mcp-server/pkg/http/middleware"
	"github.com/github/github-mcp-server/pkg/utils"
)

// TokenExtractor is a middleware.TokenExtractor that validates incoming bearer
// tokens against AuthSec (RFC 7662 introspection + RFC 8707 audience), then
// swaps the token for the configured upstream GitHub PAT so the rest of the
// server continues to call api.github.com unchanged.
//
// The validated AuthSec principal is attached to the request context via
// WithPrincipal; scope enforcement and user identity are available to tool
// handlers via GetPrincipal(ctx).
type TokenExtractor struct {
	cfg          *Config
	introspector *Introspector
	logger       *slog.Logger
}

// NewTokenExtractor builds an AuthSec-backed token extractor. cfg must be
// valid (cfg.Validate() == nil).
func NewTokenExtractor(cfg *Config, logger *slog.Logger) (*TokenExtractor, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TokenExtractor{
		cfg:          cfg,
		introspector: NewIntrospector(cfg),
		logger:       logger.With("component", "authsec"),
	}, nil
}

// Ensure it implements middleware.TokenExtractor.
var _ middleware.TokenExtractor = (*TokenExtractor)(nil)

// Extract validates the bearer token with AuthSec and returns a TokenInfo
// carrying the upstream GitHub PAT (so tools call GitHub successfully). If
// validation fails, returns utils.ErrMissingAuthorizationHeader so the
// surrounding middleware emits a 401 + WWW-Authenticate challenge.
func (e *TokenExtractor) Extract(r *http.Request) (*ghcontext.TokenInfo, error) {
	bearer, err := utils.ParseBearerAuthorizationHeader(r)
	if err != nil {
		return nil, err
	}

	ir, err := e.introspector.Introspect(r.Context(), bearer)
	if err != nil {
		e.logger.Warn("introspection call failed", "err", err)
		return nil, utils.ErrMissingAuthorizationHeader
	}
	if !ir.Active {
		e.logger.Info("authsec token inactive")
		return nil, utils.ErrMissingAuthorizationHeader
	}
	if !ir.HasAudience(e.cfg.ResourceURI) {
		e.logger.Warn("authsec token audience mismatch",
			"expected", e.cfg.ResourceURI, "got", ir.Audiences())
		return nil, utils.ErrMissingAuthorizationHeader
	}
	if err := e.checkScopes(ir); err != nil {
		e.logger.Warn("authsec scope check failed", "err", err, "scopes", ir.Scopes())
		return nil, utils.ErrMissingAuthorizationHeader
	}

	// Attach validated principal to the request context for downstream use.
	principal := principalFromIntrospection(ir)
	*r = *r.WithContext(WithPrincipal(r.Context(), principal))

	e.logger.Debug("authsec token validated",
		"sub", principal.Subject,
		"client_id", principal.ClientID,
		"context_id", principal.ContextID,
		"scopes", principal.Scopes)

	// Swap to upstream GitHub token so every downstream GitHub API call works
	// without modification.
	tokenType, err := utils.ClassifyGitHubToken(e.cfg.UpstreamGitHubToken)
	if err != nil {
		// If the configured upstream token doesn't match a known GitHub prefix
		// (unusual but possible for GitHub Enterprise test envs), fall back to
		// classic PAT type — downstream call will still fail loudly if the
		// token is actually invalid.
		tokenType = utils.TokenTypePersonalAccessToken
	}
	return &ghcontext.TokenInfo{
		Token:     e.cfg.UpstreamGitHubToken,
		TokenType: tokenType,
	}, nil
}

func (e *TokenExtractor) checkScopes(ir *IntrospectionResponse) error {
	if len(e.cfg.RequiredScopes) == 0 {
		return nil
	}
	have := make(map[string]struct{}, len(ir.Scopes()))
	for _, s := range ir.Scopes() {
		have[s] = struct{}{}
	}
	for _, req := range e.cfg.RequiredScopes {
		if _, ok := have[req]; ok {
			return nil
		}
	}
	return fmt.Errorf("token missing required scope; need one of %v", e.cfg.RequiredScopes)
}
