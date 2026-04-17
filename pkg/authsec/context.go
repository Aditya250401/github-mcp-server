package authsec

import "context"

type principalKey struct{}

// Principal is the validated AuthSec identity for a request.
type Principal struct {
	Subject   string   // sub claim
	ClientID  string   // client_id claim (Hydra client id)
	Scopes    []string // parsed space-delimited scopes
	Audiences []string // aud claim
	ContextID string   // AuthSec-specific context_id from session
	Issuer    string
	Username  string
	ExpiresAt int64
}

// WithPrincipal attaches the AuthSec principal to ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// GetPrincipal retrieves the AuthSec principal attached to ctx, if any.
func GetPrincipal(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}

// principalFromIntrospection builds a Principal from an introspection response.
func principalFromIntrospection(resp *IntrospectionResponse) *Principal {
	return &Principal{
		Subject:   resp.Sub,
		ClientID:  resp.ClientID,
		Scopes:    resp.Scopes(),
		Audiences: resp.Audiences(),
		ContextID: resp.ContextID,
		Issuer:    resp.Iss,
		Username:  resp.Username,
		ExpiresAt: resp.Exp,
	}
}
