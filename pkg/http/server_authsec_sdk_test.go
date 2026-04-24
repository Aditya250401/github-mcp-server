package http

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	localauthsec "github.com/github/github-mcp-server/pkg/authsec"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildHTTPHandler_AuthSecSDK_MetadataAndChallenges(t *testing.T) {
	t.Parallel()

	cfg, token, closeAuthSec := newAuthSecSDKServerConfig(t, map[string][]string{
		"get_me": {"agent:read"},
	})
	defer closeAuthSec()

	logger := testLogger()
	tHelper, _ := translations.TranslationHelper()
	handler, err := buildHTTPHandler(context.Background(), cfg, tHelper, logger)
	require.NoError(t, err)

	t.Run("metadata alias registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"resource":"https://mcp.example.com/mcp"`)
	})

	t.Run("bare metadata path not registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("unauthenticated mcp request gets sdk bearer challenge", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "resource_metadata=")
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp")
	})

	t.Run("authenticated tools list succeeds through sdk bridge", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		t.Logf("tools/list response: code=%d body=%s", rec.Code, rec.Body.String())
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"get_me"`)
		assert.NotContains(t, rec.Body.String(), `"create_issue"`)
	})
}

func TestBuildHTTPHandler_AuthSecSDK_DeniesUnauthorizedToolCall(t *testing.T) {
	t.Parallel()

	cfg, token, closeAuthSec := newAuthSecSDKServerConfig(t, map[string][]string{
		"get_me": {"agent:read"},
	})
	defer closeAuthSec()

	logger := testLogger()
	tHelper, _ := translations.TranslationHelper()
	handler, err := buildHTTPHandler(context.Background(), cfg, tHelper, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"octo","repo":"hello","title":"x"}}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Logf("tools/call response: code=%d body=%s", rec.Code, rec.Body.String())
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "insufficient_scope")
}

func TestBuildHTTPHandler_AuthSecSDK_UsesScopePolicyEndpoint(t *testing.T) {
	t.Parallel()

	var policyCalls atomic.Int64
	cfg, token, closeAuthSec := newAuthSecSDKServerConfigWithCounters(t, map[string][]string{
		"get_me": {"agent:read"},
	}, &policyCalls)
	defer closeAuthSec()

	logger := testLogger()
	tHelper, _ := translations.TranslationHelper()
	handler, err := buildHTTPHandler(context.Background(), cfg, tHelper, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.GreaterOrEqual(t, policyCalls.Load(), int64(1))
}

func TestBuildHTTPHandler_AuthSecSDK_BootstrapsFromLocalFallbackWhenRemotePolicyUnavailable(t *testing.T) {
	t.Parallel()

	cfg, token, closeAuthSec := newAuthSecSDKServerConfigWithOptions(t, nil, "repo", http.StatusServiceUnavailable, nil)
	defer closeAuthSec()

	logger := testLogger()
	tHelper, _ := translations.TranslationHelper()
	handler, err := buildHTTPHandler(context.Background(), cfg, tHelper, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Logf("fallback tools/list response: code=%d body=%s", rec.Code, rec.Body.String())
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"name":"search_repositories"`)
}

func newAuthSecSDKServerConfig(t *testing.T, policy map[string][]string) (*ServerConfig, string, func()) {
	t.Helper()
	var policyCalls atomic.Int64
	return newAuthSecSDKServerConfigWithOptions(t, policy, "agent:read", http.StatusOK, &policyCalls)
}

func newAuthSecSDKServerConfigWithCounters(t *testing.T, policy map[string][]string, policyCalls *atomic.Int64) (*ServerConfig, string, func()) {
	t.Helper()
	return newAuthSecSDKServerConfigWithOptions(t, policy, "agent:read", http.StatusOK, policyCalls)
}

func newAuthSecSDKServerConfigWithOptions(t *testing.T, policy map[string][]string, tokenScope string, policyStatus int, policyCalls *atomic.Int64) (*ServerConfig, string, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var authSecServer *httptest.Server
	authSecServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{{
					"kty": "RSA",
					"kid": "k1",
					"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				}},
			})
		case "/oauth/introspect":
			user, pass, ok := r.BasicAuth()
			if !ok || user != "rs-test" || pass != "secret-test" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "user-123",
				"iss":    authSecServer.URL,
				"aud":    []string{"https://mcp.example.com/mcp"},
				"scope":  tokenScope,
			})
		case "/authsec/resource-servers/rs-test/sdk-policy":
			if policyCalls != nil {
				policyCalls.Add(1)
			}
			user, pass, ok := r.BasicAuth()
			if !ok || user != "rs-test" || pass != "secret-test" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if policyStatus != http.StatusOK {
				http.Error(w, http.StatusText(policyStatus), policyStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tools": policy,
			})
		default:
			http.NotFound(w, r)
		}
	}))

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": authSecServer.URL,
		"sub": "user-123",
		"aud": []string{"https://mcp.example.com/mcp"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString(key)
	require.NoError(t, err)

	cfg := &ServerConfig{
		Version:      "test",
		Host:         "https://api.github.com",
		BaseURL:      "https://mcp.example.com",
		ResourcePath: "/mcp",
		AuthSec: &localauthsec.Config{
			Issuer:              authSecServer.URL,
			ResourceURI:         "https://mcp.example.com/mcp",
			ResourceServerID:    "rs-test",
			IntrospectionSecret: "secret-test",
			UpstreamGitHubToken: "ghu_testupstreamtoken",
			HTTPClient:          authSecServer.Client(),
			CacheTTL:            100 * time.Millisecond,
		},
	}

	return cfg, token, authSecServer.Close
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
