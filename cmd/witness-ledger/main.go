package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/google/trillian"
	"github.com/gorilla/mux"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	ariesvdr "github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"google.golang.org/grpc"

	"github.com/soluchok/witness-ledger/pkg/controller/command"
	"github.com/soluchok/witness-ledger/pkg/controller/rest"
)

const serverAddr = ":7777"

func main() { // nolint: funlen
	logIDstr, ok := os.LookupEnv("LOG_ID")
	if !ok && logIDstr == "" {
		log.Fatal("env variable LOG_ID is not set or its value empty")
	}

	logID, err := strconv.ParseInt(logIDstr, 10, 64)
	if err != nil {
		log.Fatalf("parse int LOG_ID: %v", err)
	}

	endpoint, ok := os.LookupEnv("LOG_ENDPOINT")
	if !ok && endpoint == "" {
		log.Fatal("env variable LOG_ENDPOINT is not set or its value empty")
	}

	keystoreURL, _, err := webkms.CreateKeyStore(&http.Client{}, "http://witness.ledger.kms:7878", "sdsdsd", "")
	if err != nil {
		log.Fatal(err)
	}

	rmks := webkms.New(keystoreURL, &http.Client{})

	kid, _, err := rmks.Create(kms.ECDSAP256TypeIEEEP1363)
	if err != nil {
		log.Fatal(err)
	}

	v := ariesvdr.New(
		&kmsCtx{KeyManager: webkms.New("", nil)},
		ariesvdr.WithVDR(vdrkey.New()),
	)

	wc := webcrypto.New(keystoreURL, &http.Client{})

	_ = wc
	_ = kid

	conn, err := grpc.Dial(endpoint, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			log.Println(err)
		}
	}()

	router := mux.NewRouter()

	cmd, _ := command.New(&command.Config{ // nolint: errcheck
		Trillian: trillian.NewTrillianLogClient(conn),
		KMS:      rmks,
		Crypto:   wc,
		VDR:      v,
		LogID:    logID,
		Key: command.Key{
			ID:   kid,
			Type: kms.ECDSAP256TypeIEEEP1363,
		},
		Issuers: []string{},
	})

	op, _ := rest.New(cmd) // nolint: errcheck

	for _, handler := range op.GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	if err = http.ListenAndServe(serverAddr, router); err != nil {
		log.Printf("listen and serve: %v", err)
	}
}

type kmsCtx struct{ kms.KeyManager }

func (c *kmsCtx) KMS() kms.KeyManager {
	return c.KeyManager
}
