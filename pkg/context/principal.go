package context

import stdcontext "context"

type principalCtxKey struct{}

// Principal captures an authenticated caller independently from any upstream credential model.
type Principal struct {
	Subject  string
	Issuer   string
	TenantID string
	Scopes   []string
	Claims   map[string]any
}

// WithPrincipal adds the authenticated principal to the request context.
func WithPrincipal(ctx stdcontext.Context, principal *Principal) stdcontext.Context {
	return stdcontext.WithValue(ctx, principalCtxKey{}, principal)
}

// GetPrincipal retrieves the authenticated principal from the request context.
func GetPrincipal(ctx stdcontext.Context) (*Principal, bool) {
	if principal, ok := ctx.Value(principalCtxKey{}).(*Principal); ok && principal != nil {
		return principal, true
	}
	return nil, false
}

type upstreamTokenCtxKey struct{}

// UpstreamToken represents the token used for upstream API access.
type UpstreamToken struct {
	Token  string
	Source string
}

// WithUpstreamToken adds the upstream credential to the request context.
func WithUpstreamToken(ctx stdcontext.Context, token *UpstreamToken) stdcontext.Context {
	return stdcontext.WithValue(ctx, upstreamTokenCtxKey{}, token)
}

// GetUpstreamToken retrieves the upstream credential from the request context.
func GetUpstreamToken(ctx stdcontext.Context) (*UpstreamToken, bool) {
	if token, ok := ctx.Value(upstreamTokenCtxKey{}).(*UpstreamToken); ok && token != nil {
		return token, true
	}
	return nil, false
}
