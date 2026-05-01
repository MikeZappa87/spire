package azureentra

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	// Azure Database for PostgreSQL requires this scope for AAD token auth.
	ossrdbmsScope = "https://ossrdbms-aad.database.windows.net/.default"

	// Refresh the token this far in advance of expiry.
	tokenRefreshBuffer = 2 * time.Minute
)

// nowFunc returns the current time; overridable in tests.
var nowFunc = time.Now

// tokenFetcher abstracts Azure token acquisition for testing.
type tokenFetcher interface {
	fetchToken(ctx context.Context, config *Config) (azcore.AccessToken, error)
}

// cachedToken holds a cached Azure AD access token with its expiry.
type cachedToken struct {
	mu        sync.Mutex
	token     string
	expiresOn time.Time
}

func (c *cachedToken) getToken(ctx context.Context, config *Config, fetcher tokenFetcher) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if config == nil {
		return "", errors.New("missing config")
	}

	if fetcher == nil {
		return "", errors.New("missing token fetcher")
	}

	if !c.shouldRefresh() {
		return c.token, nil
	}

	accessToken, err := fetcher.fetchToken(ctx, config)
	if err != nil {
		return "", fmt.Errorf("failed to acquire Azure access token: %w", err)
	}

	c.token = accessToken.Token
	c.expiresOn = accessToken.ExpiresOn
	return c.token, nil
}

// shouldRefresh returns true if the cached token is expired or will expire
// soon (within the tokenRefreshBuffer window).
func (c *cachedToken) shouldRefresh() bool {
	return nowFunc().Add(tokenRefreshBuffer).After(c.expiresOn)
}

// azureTokenFetcher is the production implementation that uses the Azure SDK.
type azureTokenFetcher struct{}

func (a *azureTokenFetcher) fetchToken(ctx context.Context, config *Config) (azcore.AccessToken, error) {
	cred, err := newAzureCredential(config)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{ossrdbmsScope},
	})
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("failed to get token: %w", err)
	}

	return token, nil
}

func newAzureCredential(config *Config) (azcore.TokenCredential, error) {
	opts := &azidentity.DefaultAzureCredentialOptions{}
	if config.TenantID != "" {
		opts.TenantID = config.TenantID
	}
	if config.ClientID != "" {
		opts.AdditionallyAllowedTenants = []string{"*"}
	}

	return azidentity.NewDefaultAzureCredential(opts)
}
