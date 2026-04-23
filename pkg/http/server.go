package http

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/github/github-mcp-server/pkg/authsec"
	ghcontext "github.com/github/github-mcp-server/pkg/context"
	"github.com/github/github-mcp-server/pkg/github"
	"github.com/github/github-mcp-server/pkg/http/oauth"
	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/lockdown"
	"github.com/github/github-mcp-server/pkg/observability"
	"github.com/github/github-mcp-server/pkg/observability/metrics"
	"github.com/github/github-mcp-server/pkg/scopes"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/github/github-mcp-server/pkg/utils"
	"github.com/go-chi/chi/v5"
)

// knownFeatureFlags are the feature flags that can be enabled via X-MCP-Features header.
// Only these flags are accepted from headers.
var knownFeatureFlags = []string{}

type ServerConfig struct {
	// Version of the server
	Version string

	// GitHub Host to target for API requests (e.g. github.com or github.enterprise.com)
	Host string

	// Port to listen on (default: 8082)
	Port int

	// BaseURL is the publicly accessible URL of this server for OAuth resource metadata.
	// If not set, the server will derive the URL from incoming request headers.
	BaseURL string

	// ResourcePath is the externally visible base path for this server (e.g., "/mcp").
	// This is used to restore the original path when a proxy strips a base path before forwarding.
	ResourcePath string

	// ExportTranslations indicates if we should export translations
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#i18n--overriding-descriptions
	ExportTranslations bool

	// EnableCommandLogging indicates if we should log commands
	EnableCommandLogging bool

	// Path to the log file if not stderr
	LogFilePath string

	// Content window size
	ContentWindowSize int

	// LockdownMode indicates if we should enable lockdown mode
	LockdownMode bool

	// RepoAccessCacheTTL overrides the default TTL for repository access cache entries.
	RepoAccessCacheTTL *time.Duration

	// ScopeChallenge indicates if we should return OAuth scope challenges, and if we should perform
	// tool filtering based on token scopes.
	ScopeChallenge bool

	// ReadOnly indicates if we should only register read-only tools.
	// When set via CLI flag, this acts as an upper bound — per-request headers
	// cannot re-enable write tools.
	ReadOnly bool

	// EnabledToolsets is a list of toolsets to enable.
	// When set via CLI flag, per-request headers can only narrow within these toolsets.
	EnabledToolsets []string

	// EnabledTools is a list of specific tools to enable (additive to toolsets).
	EnabledTools []string

	// DynamicToolsets enables dynamic toolset discovery mode.
	DynamicToolsets bool

	// ExcludeTools is a list of tool names to disable regardless of other settings.
	// When set via CLI flag, per-request headers cannot re-include these tools.
	ExcludeTools []string

	// InsidersMode indicates if we should enable experimental features.
	InsidersMode bool

	// AuthSec, when non-nil and valid, enables AuthSec-backed token validation.
	// In HTTP mode the generic AuthSec Go SDK becomes the canonical MCP
	// protection layer and the GitHub MCP server only bridges the validated
	// principal into its existing upstream GitHub token plumbing.
	AuthSec *authsec.Config
}

func RunHTTPServer(cfg ServerConfig) error {
	// Create app context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	t, dumpTranslations := translations.TranslationHelper()

	var slogHandler slog.Handler
	var logOutput io.Writer
	if cfg.LogFilePath != "" {
		file, err := os.OpenFile(cfg.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		logOutput = file
		slogHandler = slog.NewTextHandler(logOutput, &slog.HandlerOptions{Level: slog.LevelDebug})
	} else {
		logOutput = os.Stderr
		slogHandler = slog.NewTextHandler(logOutput, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(slogHandler)
	logger.Info("starting server", "version", cfg.Version, "host", cfg.Host, "lockdownEnabled", cfg.LockdownMode, "readOnly", cfg.ReadOnly, "insidersMode", cfg.InsidersMode)

	handler, err := buildHTTPHandler(ctx, &cfg, t, logger)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	httpSvr := http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		logger.Info("shutting down server")
		if err := httpSvr.Shutdown(shutdownCtx); err != nil {
			logger.Error("error during server shutdown", "error", err)
		}
	}()

	if cfg.ExportTranslations {
		// Once server is initialized, all translations are loaded
		dumpTranslations()
	}

	logger.Info("HTTP server listening", "addr", addr)
	if err := httpSvr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server error: %w", err)
	}

	logger.Info("server stopped gracefully")
	return nil
}

func buildHTTPHandler(ctx context.Context, cfg *ServerConfig, t translations.TranslationHelperFunc, logger *slog.Logger) (http.Handler, error) {
	apiHost, err := utils.NewAPIHost(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API host: %w", err)
	}

	repoAccessOpts := []lockdown.RepoAccessOption{
		lockdown.WithLogger(logger.With("component", "lockdown")),
	}
	if cfg.RepoAccessCacheTTL != nil {
		repoAccessOpts = append(repoAccessOpts, lockdown.WithTTL(*cfg.RepoAccessCacheTTL))
	}

	featureChecker := createHTTPFeatureChecker()

	obs, err := observability.NewExporters(logger, metrics.NewNoopMetrics())
	if err != nil {
		return nil, fmt.Errorf("failed to create observability exporters: %w", err)
	}

	deps := github.NewRequestDeps(
		apiHost,
		cfg.Version,
		cfg.LockdownMode,
		repoAccessOpts,
		t,
		cfg.ContentWindowSize,
		featureChecker,
		obs,
	)

	if err := initGlobalToolScopeMap(t); err != nil {
		return nil, fmt.Errorf("failed to initialize tool scope map: %w", err)
	}

	effectiveResourcePath := normalizeMountPath(cfg.ResourcePath)
	if cfg.AuthSec != nil && cfg.AuthSec.Enabled() && effectiveResourcePath == "" {
		effectiveResourcePath = "/mcp"
	}
	cfg.ResourcePath = effectiveResourcePath

	oauthCfg := &oauth.Config{
		BaseURL:                cfg.BaseURL,
		ResourcePath:           cfg.ResourcePath,
		ResourceName:           "GitHub MCP Server",
		ScopesSupported:        oauth.SupportedScopes,
		BearerMethodsSupported: []string{"header"},
	}

	serverOptions := []HandlerOption{
		WithFeatureChecker(featureChecker),
		WithOAuthConfig(oauthCfg),
	}
	if cfg.ScopeChallenge && !(cfg.AuthSec != nil && cfg.AuthSec.Enabled()) {
		scopeFetcher := scopes.NewFetcher(apiHost, scopes.FetcherOptions{})
		serverOptions = append(serverOptions, WithScopeFetcher(scopeFetcher))
	}

	handler := NewHTTPMcpHandler(ctx, cfg, deps, t, logger, apiHost, serverOptions...)

	// AuthSec SDK mode owns metadata, bearer challenges, token validation, tool
	// authorization, and tools/list filtering. The inner GitHub server only sees
	// a bridged upstream GitHub credential and the validated principal.
	if cfg.AuthSec != nil && cfg.AuthSec.Enabled() {
		rt, err := authsec.NewSDKRuntime(cfg.AuthSec, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create AuthSec SDK runtime: %w", err)
		}
		metadataPath, err := cfg.AuthSec.MetadataPath()
		if err != nil {
			return nil, err
		}

		inner := chi.NewRouter()
		handler.RegisterMiddleware(inner)
		handler.RegisterRoutes(inner)

		outer := chi.NewRouter()
		outer.Handle(metadataPath, rt.ProtectedResourceHandler())
		outer.Mount(cfg.ResourcePath, rt.Wrap(authsec.BridgeToGitHubContext(inner, cfg.AuthSec, logger)))

		logger.Info("AuthSec SDK protection enabled",
			"issuer", cfg.AuthSec.Issuer,
			"resource_uri", cfg.AuthSec.ResourceURI,
			"resource_server_id", cfg.AuthSec.ResourceServerID,
			"mcp_path", cfg.ResourcePath,
			"metadata_path", metadataPath)
		return outer, nil
	}

	oauthHandler, err := oauth.NewAuthHandler(oauthCfg, apiHost)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth handler: %w", err)
	}

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		handler.RegisterMiddleware(r)
		handler.RegisterRoutes(r)
	})
	logger.Info("MCP endpoints registered", "baseURL", cfg.BaseURL)

	r.Group(func(r chi.Router) {
		oauthHandler.RegisterRoutes(r)
	})
	logger.Info("OAuth protected resource endpoints registered", "baseURL", cfg.BaseURL)

	return r, nil
}

func initGlobalToolScopeMap(t translations.TranslationHelperFunc) error {
	// Build inventory with all tools to extract scope information
	inv, err := inventory.NewBuilder().
		SetTools(github.AllTools(t)).
		Build()

	if err != nil {
		return fmt.Errorf("failed to build inventory for tool scope map: %w", err)
	}

	// Initialize the global scope map
	scopes.SetToolScopeMapFromInventory(inv)

	return nil
}

// createHTTPFeatureChecker creates a feature checker that reads header features from context
// and validates them against the knownFeatureFlags whitelist
func createHTTPFeatureChecker() inventory.FeatureFlagChecker {
	// Pre-compute whitelist as set for O(1) lookup
	knownSet := make(map[string]bool, len(knownFeatureFlags))
	for _, f := range knownFeatureFlags {
		knownSet[f] = true
	}

	return func(ctx context.Context, flag string) (bool, error) {
		if knownSet[flag] && slices.Contains(ghcontext.GetHeaderFeatures(ctx), flag) {
			return true, nil
		}
		return false, nil
	}
}

func normalizeMountPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || trimmed == "/" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return strings.TrimRight(trimmed, "/")
}
