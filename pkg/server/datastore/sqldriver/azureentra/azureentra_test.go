package azureentra

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

const (
	fakeSQLDriverName  = "fake-azure-sql-driver"
	postgresConnString = "dbname=postgres user=postgres host=the-host sslmode=require"
)

var fakeSQLDriverWrapper = &sqlDriverWrapper{
	sqlDriver:    &fakeSQLDriver{},
	tokenFetcher: &fakeTokenFetcher{},
	tokensMap:    make(tokens),
}

func init() {
	sql.Register(fakeSQLDriverName, fakeSQLDriverWrapper)
}

func TestAzureEntra(t *testing.T) {
	t.Setenv("PGPASSWORD", "")

	testCases := []struct {
		name          string
		config        *Config
		tokenFetcher  *fakeTokenFetcher
		expectedError string
	}{
		{
			name: "postgres - success",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: postgresConnString,
			},
			tokenFetcher: &fakeTokenFetcher{
				token: azcore.AccessToken{
					Token:     "fake-azure-token",
					ExpiresOn: time.Now().Add(time.Hour),
				},
			},
		},
		{
			name: "postgres - success with tenant id",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: postgresConnString,
				TenantID:   "my-tenant-id",
			},
			tokenFetcher: &fakeTokenFetcher{
				token: azcore.AccessToken{
					Token:     "fake-azure-token",
					ExpiresOn: time.Now().Add(time.Hour),
				},
			},
		},
		{
			name: "postgres - password already present",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: "password=the-password",
			},
			tokenFetcher: &fakeTokenFetcher{
				token: azcore.AccessToken{
					Token:     "fake-azure-token",
					ExpiresOn: time.Now().Add(time.Hour),
				},
			},
			expectedError: "unexpected password in connection string for Azure Entra authentication",
		},
		{
			name: "postgres - invalid connection string",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: "not-valid!",
			},
			tokenFetcher: &fakeTokenFetcher{
				token: azcore.AccessToken{
					Token:     "fake-azure-token",
					ExpiresOn: time.Now().Add(time.Hour),
				},
			},
			expectedError: "could not parse connection string: cannot parse `not-valid!`: failed to parse as keyword/value (invalid keyword/value)",
		},
		{
			name: "token fetch error",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: postgresConnString,
			},
			tokenFetcher: &fakeTokenFetcher{
				err: errors.New("azure auth failed"),
			},
			expectedError: "could not get access token: failed to acquire Azure access token: azure auth failed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dsn, err := testCase.config.FormatDSN()
			require.NoError(t, err)

			fakeSQLDriverWrapper.tokenFetcher = testCase.tokenFetcher
			fakeSQLDriverWrapper.tokensMap = make(tokens)

			db, err := gorm.Open(fakeSQLDriverName, dsn)
			if testCase.expectedError != "" {
				require.EqualError(t, err, testCase.expectedError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, db)
		})
	}
}

func TestCacheToken(t *testing.T) {
	config := &Config{
		DriverName: PostgresDriverName,
		ConnString: postgresConnString,
	}
	dsn, err := config.FormatDSN()
	require.NoError(t, err)

	initialTime := time.Now().UTC()

	// Set a first token
	firstToken := azcore.AccessToken{
		Token:     "first-token",
		ExpiresOn: initialTime.Add(time.Hour),
	}
	fakeSQLDriverWrapper.tokenFetcher = &fakeTokenFetcher{token: firstToken}
	fakeSQLDriverWrapper.tokensMap = make(tokens)

	// Should have no cached token
	require.Empty(t, fakeSQLDriverWrapper.tokensMap[dsn])

	// Open should cache the token
	db, err := gorm.Open(fakeSQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	// Retrieve cached token
	token, err := fakeSQLDriverWrapper.tokensMap[dsn].getToken(context.Background(), config, fakeSQLDriverWrapper.tokenFetcher)
	require.NoError(t, err)
	require.Equal(t, "first-token", token)

	// Set a new token to be returned by the fetcher
	secondToken := azcore.AccessToken{
		Token:     "second-token",
		ExpiresOn: initialTime.Add(2 * time.Hour),
	}
	fakeSQLDriverWrapper.tokenFetcher = &fakeTokenFetcher{token: secondToken}

	// Advance clock just a few seconds — should still use cached token
	nowFunc = func() time.Time { return initialTime.Add(time.Second * 15) }
	defer func() { nowFunc = time.Now }()

	db, err = gorm.Open(fakeSQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	token, err = fakeSQLDriverWrapper.tokensMap[dsn].getToken(context.Background(), config, fakeSQLDriverWrapper.tokenFetcher)
	require.NoError(t, err)
	require.Equal(t, "first-token", token)

	// Advance clock past expiry minus refresh buffer — should get new token
	nowFunc = func() time.Time { return initialTime.Add(time.Hour - tokenRefreshBuffer + time.Second) }

	db, err = gorm.Open(fakeSQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	token, err = fakeSQLDriverWrapper.tokensMap[dsn].getToken(context.Background(), config, fakeSQLDriverWrapper.tokenFetcher)
	require.NoError(t, err)
	require.Equal(t, "second-token", token)
}

func TestFormatDSN(t *testing.T) {
	config := &Config{
		TenantID:   "tenant-id",
		ClientID:   "client-id",
		DriverName: PostgresDriverName,
		ConnString: postgresConnString,
	}

	dsn, err := config.FormatDSN()
	require.NoError(t, err)
	require.Contains(t, dsn, `"tenant_id":"tenant-id"`)
	require.Contains(t, dsn, `"client_id":"client-id"`)
	require.Contains(t, dsn, `"driver_name":"azure-entra-postgres"`)
}

type fakeTokenFetcher struct {
	token azcore.AccessToken
	err   error
}

func (f *fakeTokenFetcher) fetchToken(_ context.Context, _ *Config) (azcore.AccessToken, error) {
	return f.token, f.err
}

type fakeSQLDriver struct {
	err error
}

func (d *fakeSQLDriver) Open(string) (driver.Conn, error) {
	return nil, d.err
}
