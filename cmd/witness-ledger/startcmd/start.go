package startcmd

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/trillian"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ariesvdr "github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/soluchok/witness-ledger/pkg/controller/command"
	"github.com/soluchok/witness-ledger/pkg/controller/rest"
)

const (
	envPrefix = "WL_"

	agentHostFlagName      = "api-host"
	agentHostEnvKey        = envPrefix + "API_HOST"
	agentHostFlagShorthand = "a"
	agentHostFlagUsage     = "Host Name:Port." +
		" Alternatively, this can be set with the following environment variable: " + agentHostEnvKey

	logIDFlagName      = "log-id"
	logIDEnvKey        = envPrefix + "LOG_ID"
	logIDFlagShorthand = "l"
	logIDFlagUsage     = "Trillian log id." +
		" Alternatively, this can be set with the following environment variable: " + logIDEnvKey

	logEndpointFlagName      = "log-endpoint"
	logEndpointEnvKey        = envPrefix + "LOG_ENDPOINT"
	logEndpointFlagShorthand = "e"
	logEndpointFlagUsage     = "Trillian log id." +
		" Alternatively, this can be set with the following environment variable: " + logEndpointEnvKey

	kmsStoreEndpointFlagName      = "kms-store-endpoint"
	kmsStoreEndpointEnvKey        = envPrefix + "KMS_STORE_ENDPOINT"
	kmsStoreEndpointFlagShorthand = "k"
	kmsStoreEndpointFlagUsage     = "Remote KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsStoreEndpointEnvKey

	keyIDFlagName      = "key-id"
	keyIDEnvKey        = envPrefix + "KEY_ID"
	keyIDFlagShorthand = "i"
	keyIDFlagUsage     = "Key ID." +
		" Alternatively, this can be set with the following environment variable: " + keyIDEnvKey

	keyTypeFlagName      = "key-type"
	keyTypeEnvKey        = envPrefix + "KEY_TYPE"
	keyTypeFlagShorthand = "t"
	keyTypeFlagUsage     = "Key type." +
		" Alternatively, this can be set with the following environment variable: " + keyTypeEnvKey

	datasourceNameFlagName      = "dsn"
	datasourceNameFlagShorthand = "d"
	datasourceNameFlagUsage     = "Datasource Name with credentials if required." +
		" Format must be <driver>:[//]<driver-specific-dsn>." +
		" Examples: 'mysql://root:secret@tcp(localhost:3306)/adapter', 'mem://test'." +
		" Supported drivers are [mem, couchdb, mysql]." +
		" Alternatively, this can be set with the following environment variable: " + datasourceNameEnvKey
	datasourceNameEnvKey = envPrefix + "DSN"

	datasourceTimeoutFlagName  = "dsn-timeout"
	datasourceTimeoutFlagUsage = "Total time in seconds to wait until the datasource is available before giving up." +
		" Default: 30 seconds." +
		" Alternatively, this can be set with the following environment variable: " + datasourceTimeoutEnvKey
	datasourceTimeoutEnvKey = envPrefix + "DSN_TIMEOUT"
)

const (
	databaseTypeMemOption     = "mem"
	databaseTypeMySQLOption   = "mysql"
	databaseTypeCouchDBOption = "couchdb"
)

var logger = log.New("witness-ledger/startcmd")

// nolint:gochecknoglobals
var supportedStorageProviders = map[string]func(string, string) (storage.Provider, error){
	databaseTypeCouchDBOption: func(dsn, prefix string) (storage.Provider, error) {
		return couchdb.NewProvider(dsn, couchdb.WithDBPrefix(prefix)) // nolint: wrapcheck
	},
	databaseTypeMySQLOption: func(dsn, prefix string) (storage.Provider, error) {
		return mysql.NewProvider(dsn, mysql.WithDBPrefix(prefix)) // nolint: wrapcheck
	},
	databaseTypeMemOption: func(_, _ string) (storage.Provider, error) { // nolint: unparam
		return mem.NewProvider(), nil
	},
}

type server interface {
	ListenAndServe(host string, router http.Handler, certFile, keyFile string) error
}

// HTTPServer represents an actual server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler, certFile, keyFile string) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router) // nolint: wrapcheck
	}

	return http.ListenAndServe(host, router) // nolint: wrapcheck
}

// Cmd returns the Cobra start command.
func Cmd(server server) (*cobra.Command, error) {
	startCmd := createStartCMD(server)

	createFlags(startCmd)

	return startCmd, nil
}

type agentParameters struct {
	logID             int64
	host              string
	logEndpoint       string
	keyID             string
	keyType           kms.KeyType
	datasourceName    string
	datasourceTimeout uint64
	datasourcePrefix  string
	kmsStoreEndpoint  string
	tlsCertFile       string
	tlsKeyFile        string
	server            server
}

func createStartCMD(server server) *cobra.Command { // nolint: funlen
	return &cobra.Command{
		Use:   "start",
		Short: "Start an agent",
		Long:  `Starts witness-ledger service`,
		RunE: func(cmd *cobra.Command, args []string) error {
			host, err := getUserSetVar(cmd, agentHostFlagName, agentHostEnvKey, false)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", agentHostFlagName, agentHostEnvKey, err)
			}

			logIDVal, err := getUserSetVar(cmd, logIDFlagName, logIDEnvKey, false)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", logIDFlagName, logIDEnvKey, err)
			}

			logID, err := strconv.ParseInt(logIDVal, 10, 64)
			if err != nil {
				return fmt.Errorf("log ID is not a number: %w", err)
			}

			logEndpoint, err := getUserSetVar(cmd, logEndpointFlagName, logEndpointEnvKey, false)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", logEndpointFlagName, logEndpointEnvKey, err)
			}

			kmsStoreEndpoint, err := getUserSetVar(cmd, kmsStoreEndpointFlagName, kmsStoreEndpointEnvKey, true)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", kmsStoreEndpointFlagName, kmsStoreEndpointEnvKey, err)
			}

			datasourceName, err := getUserSetVar(cmd, datasourceNameFlagName, datasourceNameEnvKey, kmsStoreEndpoint != "")
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", datasourceNameFlagName, datasourceNameEnvKey, err)
			}

			datasourceTimeoutStr, err := getUserSetVar(cmd, datasourceTimeoutFlagName, datasourceTimeoutEnvKey, true)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", datasourceTimeoutFlagName, datasourceTimeoutEnvKey, err)
			}

			datasourceTimeout, err := strconv.ParseUint(datasourceTimeoutStr, 10, 64)
			if err != nil {
				return fmt.Errorf("timeout is not a number(positive): %w", err)
			}

			keyID, err := getUserSetVar(cmd, keyIDFlagName, keyIDEnvKey, true)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", keyIDFlagName, keyIDEnvKey, err)
			}

			keyType, err := getUserSetVar(cmd, keyTypeFlagName, keyTypeEnvKey, true)
			if err != nil {
				return fmt.Errorf("get variable (%s or %s): %w", keyTypeFlagName, keyTypeEnvKey, err)
			}

			parameters := &agentParameters{
				server:            server,
				host:              host,
				logID:             logID,
				logEndpoint:       logEndpoint,
				kmsStoreEndpoint:  kmsStoreEndpoint,
				keyID:             keyID,
				keyType:           kms.KeyType(keyType),
				datasourceName:    datasourceName,
				datasourceTimeout: datasourceTimeout,
			}

			return startAgent(parameters)
		},
	}
}

const defaultMasterKeyURI = "local-lock://default/master/key/"

func createKMSAndCrypto(parameters *agentParameters, client *http.Client,
	store storage.Provider) (kms.KeyManager, ariescrypto.Crypto, error) {
	endpoint := parameters.kmsStoreEndpoint

	if endpoint != "" {
		return webkms.New(endpoint, client), webcrypto.New(endpoint, client), nil
	}

	local, err := localkms.New(defaultMasterKeyURI, &kmsProvider{
		storageProvider: store,
		secretLock:      &noop.NoLock{},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create kms: %w", err)
	}

	cr, err := tinkcrypto.New()
	if err != nil {
		return nil, nil, fmt.Errorf("create crypto: %w", err)
	}

	return local, cr, nil
}

func createKID(km kms.KeyManager, parameters *agentParameters) error {
	var err error

	parameters.keyID, _, err = km.Create(parameters.keyType)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}

	logger.Infof("Key id %s was created and will be used in a service", parameters.keyID)

	return nil
}

func startAgent(parameters *agentParameters) error { // nolint: funlen
	store, err := createStoreProvider(
		parameters.datasourceName,
		parameters.datasourceTimeout,
		parameters.datasourcePrefix,
	)
	if err != nil {
		return fmt.Errorf("create store provider: %w", err)
	}

	defer func() {
		if err = store.Close(); err != nil {
			logger.Errorf("store close: %v", err)
		}
	}()

	km, cr, err := createKMSAndCrypto(parameters, &http.Client{}, store)
	if err != nil {
		return fmt.Errorf("create kms and crypto: %w", err)
	}

	if parameters.keyID == "" {
		if err = createKID(km, parameters); err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	conn, err := grpc.Dial(parameters.logEndpoint, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			logger.Errorf("connection close: %v", err)
		}
	}()

	cmd, err := command.New(&command.Config{
		Trillian: trillian.NewTrillianLogClient(conn),
		KMS:      km,
		Crypto:   cr,
		VDR:      ariesvdr.New(&kmsCtx{KeyManager: km}, ariesvdr.WithVDR(vdrkey.New())),
		LogID:    parameters.logID,
		Key: command.Key{
			ID:   parameters.keyID,
			Type: parameters.keyType,
		},
		Issuers: []string{},
	})
	if err != nil {
		return fmt.Errorf("create command instance: %w", err)
	}

	op, err := rest.New(cmd)
	if err != nil {
		return fmt.Errorf("create rest instance: %w", err)
	}

	router := mux.NewRouter()

	for _, handler := range op.GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting witness-ledger on host [%s]", parameters.host)

	return parameters.server.ListenAndServe( // nolint: wrapcheck
		parameters.host,
		router,
		parameters.tlsCertFile,
		parameters.tlsKeyFile,
	)
}

func getUserSetVar(cmd *cobra.Command, flagName, envKey string, isOptional bool) (string, error) {
	defaultOrFlagVal, err := cmd.Flags().GetString(flagName)
	if cmd.Flags().Changed(flagName) {
		return defaultOrFlagVal, err // nolint: wrapcheck
	}

	value, isSet := os.LookupEnv(envKey)
	if isSet {
		return value, nil
	}

	if isOptional || defaultOrFlagVal != "" {
		return defaultOrFlagVal, nil
	}

	return "", fmt.Errorf("neither %s (command line flag) nor %s (environment variable) have been set",
		flagName, envKey)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(agentHostFlagName, agentHostFlagShorthand, "", agentHostFlagUsage)
	startCmd.Flags().Int64P(logIDFlagName, logIDFlagShorthand, 0, logIDFlagUsage)
	startCmd.Flags().StringP(logEndpointFlagName, logEndpointFlagShorthand, "", logEndpointFlagUsage)
	startCmd.Flags().StringP(kmsStoreEndpointFlagName, kmsStoreEndpointFlagShorthand, "", kmsStoreEndpointFlagUsage)
	startCmd.Flags().StringP(keyIDFlagName, keyIDFlagShorthand, "", keyIDFlagUsage)
	startCmd.Flags().StringP(keyTypeFlagName, keyTypeFlagShorthand, string(kms.ECDSAP256TypeIEEEP1363), keyTypeFlagUsage)
	startCmd.Flags().StringP(datasourceNameFlagName, datasourceNameFlagShorthand, "mem://test", datasourceNameFlagUsage)
	startCmd.Flags().String(datasourceTimeoutFlagName, "30", datasourceTimeoutFlagUsage)
}

func createStoreProvider(dbURL string, timeout uint64, prefix string) (storage.Provider, error) {
	driver, dsn, err := getDBParams(dbURL)
	if err != nil {
		return nil, err
	}

	providerFunc, supported := supportedStorageProviders[driver]
	if !supported {
		return nil, fmt.Errorf("unsupported storage driver: %s", driver)
	}

	var store storage.Provider

	return store, backoff.RetryNotify(func() error { // nolint: wrapcheck
		store, err = providerFunc(dsn, prefix)

		return err
	}, backoff.WithMaxRetries(
		backoff.NewConstantBackOff(time.Second),
		timeout,
	), func(retryErr error, t time.Duration) {
		logger.Warnf("failed to connect to storage, will sleep for %s before trying again : %v", t, retryErr)
	})
}

func getDBParams(dbURL string) (driver, dsn string, err error) {
	const urlParts = 2

	parsed := strings.SplitN(dbURL, ":", urlParts)

	if len(parsed) != urlParts {
		return "", "", fmt.Errorf("invalid dbURL %s", dbURL)
	}

	return parsed[0], strings.TrimPrefix(parsed[1], "//"), nil
}

type kmsCtx struct{ kms.KeyManager }

func (c *kmsCtx) KMS() kms.KeyManager {
	return c.KeyManager
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}
