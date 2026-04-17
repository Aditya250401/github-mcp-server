// Package authsec wraps the AuthSec (https://authnull.com) third-party OAuth
// authorization server into the GitHub MCP Server HTTP mode.
//
// It provides:
//   - Introspection (RFC 7662) of incoming bearer tokens against AuthSec.
//   - Audience validation (RFC 8707) against this resource server's resource_uri.
//   - Optional scope enforcement.
//   - Token swapping: the validated AuthSec access token is replaced in the
//     request context with an upstream GitHub PAT/App token, so every existing
//     GitHub tool in this server continues to work unchanged.
//   - Wiring into the OAuth Protected Resource Metadata (RFC 9728) handler so
//     clients discover AuthSec as the authorization server.
//
// Typical flow:
//
//	client -- Bearer AUTHSEC_AT --> MCP server
//	                                  │
//	                                  ▼
//	                       authsec.TokenExtractor
//	                       POST /oauth/introspect (Basic auth: RS_ID:secret)
//	                                  │
//	                                  ▼
//	                       if active && aud==resource_uri
//	                          replace token with upstream GitHub PAT
//	                          proceed with normal GitHub tool execution
//	                       else
//	                          401 + WWW-Authenticate: resource_metadata=...
//
// Enable via environment variables (all required):
//
//	AUTHSEC_ISSUER              e.g. https://authsec.example
//	AUTHSEC_RESOURCE_URI        e.g. https://20-106-226-245.sslip.io/mcp
//	AUTHSEC_RESOURCE_SERVER_ID  UUID of the RS record
//	AUTHSEC_INTROSPECTION_SECRET  sec_* secret from AuthSec RS creation
//	AUTHSEC_UPSTREAM_GITHUB_TOKEN GitHub PAT/App token used to call api.github.com
package authsec
