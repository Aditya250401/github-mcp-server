package middleware

import (
	"net/http"

	ghcontext "github.com/github/github-mcp-server/pkg/context"
	"github.com/github/github-mcp-server/pkg/http/oauth"
	"github.com/github/github-mcp-server/pkg/utils"
)

// TokenExtractor isolates request-token extraction from the middleware chain.
type TokenExtractor interface {
	Extract(r *http.Request) (*ghcontext.TokenInfo, error)
}

// ChallengeWriter isolates unauthorized-response generation from token extraction.
type ChallengeWriter interface {
	WriteUnauthorized(w http.ResponseWriter, r *http.Request)
}

type githubTokenExtractor struct{}

func (githubTokenExtractor) Extract(r *http.Request) (*ghcontext.TokenInfo, error) {
	tokenType, token, err := utils.ParseAuthorizationHeader(r)
	if err != nil {
		return nil, err
	}

	return &ghcontext.TokenInfo{
		Token:     token,
		TokenType: tokenType,
	}, nil
}

type oauthChallengeWriter struct {
	oauthCfg *oauth.Config
}

func (w oauthChallengeWriter) WriteUnauthorized(resp http.ResponseWriter, r *http.Request) {
	sendAuthChallenge(resp, r, w.oauthCfg)
}

// DefaultTokenExtractor preserves the current GitHub-token behavior.
func DefaultTokenExtractor() TokenExtractor {
	return githubTokenExtractor{}
}

// DefaultChallengeWriter preserves the current protected-resource challenge behavior.
func DefaultChallengeWriter(oauthCfg *oauth.Config) ChallengeWriter {
	return oauthChallengeWriter{oauthCfg: oauthCfg}
}
