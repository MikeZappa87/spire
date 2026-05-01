package azureentra

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
)

const (
	PostgresDriverName  = "azure-entra-postgres"
	getAuthTokenTimeout = time.Second * 30
)

// Config holds the configuration settings to authenticate to an
// Azure Database for PostgreSQL using Entra (Azure AD) authentication.
type Config struct {
	TenantID   string `json:"tenant_id"`
	ClientID   string `json:"client_id"`
	DriverName string `json:"driver_name"`
	ConnString string `json:"conn_string"`
}

func init() {
	registerPostgres()
}

// FormatDSN returns a DSN string based on the configuration.
func (c *Config) FormatDSN() (string, error) {
	dsn, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("could not format DSN: %w", err)
	}
	return string(dsn), nil
}

type tokens map[string]*cachedToken

// sqlDriverWrapper is a wrapper for the PostgreSQL driver, adding Azure Entra
// token-based authentication.
type sqlDriverWrapper struct {
	sqlDriver    driver.Driver
	tokenFetcher tokenFetcher

	tokensMapMtx sync.Mutex
	tokensMap    tokens
}

// Open overrides the standard Open method to inject an Azure Entra access
// token as the PostgreSQL password.
func (w *sqlDriverWrapper) Open(name string) (driver.Conn, error) {
	if w.sqlDriver == nil {
		return nil, errors.New("missing sql driver")
	}

	if w.tokenFetcher == nil {
		return nil, errors.New("missing token fetcher")
	}

	config := new(Config)
	if err := json.Unmarshal([]byte(name), config); err != nil {
		return nil, fmt.Errorf("could not unmarshal configuration: %w", err)
	}

	w.tokensMapMtx.Lock()
	token, ok := w.tokensMap[name]
	if !ok {
		token = &cachedToken{}
		w.tokensMap[name] = token
	}
	w.tokensMapMtx.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), getAuthTokenTimeout)
	defer cancel()
	password, err := token.getToken(ctx, config, w.tokenFetcher)
	if err != nil {
		return nil, fmt.Errorf("could not get access token: %w", err)
	}

	connStringWithPassword, err := addPasswordToPostgresConnString(config.ConnString, password)
	if err != nil {
		return nil, err
	}

	return w.sqlDriver.Open(connStringWithPassword)
}

func addPasswordToPostgresConnString(connString, password string) (string, error) {
	cfg, err := pgx.ParseConfig(connString)
	if err != nil {
		return "", fmt.Errorf("could not parse connection string: %w", err)
	}
	if cfg.Password != "" {
		return "", errors.New("unexpected password in connection string for Azure Entra authentication")
	}
	return fmt.Sprintf("%s password='%s'", connString, escapeSpecialCharsPostgres(password)), nil
}

// escapeSpecialCharsPostgres escapes single quotes and backslashes within a
// keyword/value postgres connection string value.
func escapeSpecialCharsPostgres(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`)
}

func registerPostgres() {
	d, ok := gorm.GetDialect("postgres")
	if !ok {
		panic("could not find postgres dialect")
	}

	gorm.RegisterDialect(PostgresDriverName, d)
	sql.Register(PostgresDriverName, &sqlDriverWrapper{
		sqlDriver:    &pq.Driver{},
		tokenFetcher: &azureTokenFetcher{},
		tokensMap:    make(tokens),
	})
}
