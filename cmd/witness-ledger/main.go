package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/gorilla/mux"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	ariesvdr "github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"google.golang.org/grpc"

	"github.com/soluchok/witness-ledger/pkg/controller/command"
	"github.com/soluchok/witness-ledger/pkg/controller/rest"
)

const serverAddr = ":7777"

type merkleLeafType uint64

const timestampedEntryLeafType merkleLeafType = 0

type logEntryType uint64

const vcLogEntryType logEntryType = 0

type version uint64

const v1 version = 0

type merkleTreeLeaf struct {
	Version          version
	LeafType         merkleLeafType
	TimestampedEntry *timestampedEntry
}

type timestampedEntry struct {
	Timestamp  uint64
	EntryType  logEntryType
	VCEntry    *verifiable.Credential
	Extensions []byte
}

type addChainResponse struct {
	SCTVersion version `json:"sct_version"`
	ID         []byte  `json:"id"`
	Timestamp  uint64  `json:"timestamp"`
	Extensions string  `json:"extensions"`
	Signature  []byte  `json:"signature"`
}

type leafEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type getEntriesResponse struct {
	Entries []leafEntry `json:"entries"`
}

type getProofByHashResponse struct {
	LeafIndex int64    `json:"leaf_index"`
	AuditPath [][]byte `json:"audit_path"`
}

type getEntryAndProofResponse struct {
	LeafInput []byte   `json:"leaf_input"`
	ExtraData []byte   `json:"extra_data"`
	AuditPath [][]byte `json:"audit_path"`
}

var errValidation = errors.New("data is not valid")

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

	srv := newService(trillian.NewTrillianLogClient(conn), v, logID)
	_ = srv

	router := mux.NewRouter()

	cmd, _ := command.New(trillian.NewTrillianLogClient(conn), rmks, wc, logID, command.Key{ // nolint: errcheck
		ID:   kid,
		Type: kms.ECDSAP256TypeIEEEP1363,
	})
	op, _ := rest.New(cmd) // nolint: errcheck

	for _, handler := range op.GetRESTHandlers() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	router.HandleFunc("/ct/v1/add-chain", srv.addChainHandler).Methods(http.MethodPost)
	router.HandleFunc("/ct/v1/get-proof-by-hash", srv.getProofByHash).Methods(http.MethodGet)
	router.HandleFunc("/ct/v1/get-entries", srv.getEntriesHandler).Methods(http.MethodGet)
	router.HandleFunc("/ct/v1/get-roots", srv.getRootsHandler).Methods(http.MethodGet)
	router.HandleFunc("/ct/v1/get-entry-and-proof", srv.getEntryAndProofHandler).Methods(http.MethodGet)

	if err = http.ListenAndServe(serverAddr, router); err != nil {
		log.Printf("listen and serve: %v", err)
	}
}

type kmsCtx struct{ kms.KeyManager }

func (c *kmsCtx) KMS() kms.KeyManager {
	return c.KeyManager
}

type service struct {
	client trillian.TrillianLogClient
	vdr    vdr.Registry
	logID  int64
}

func newService(client trillian.TrillianLogClient, v vdr.Registry, logID int64) *service {
	return &service{client: client, vdr: v, logID: logID}
}

func (s *service) addChainHandler(rw http.ResponseWriter, req *http.Request) { //nolint: funlen
	var dest bytes.Buffer

	_, err := io.Copy(&dest, req.Body)
	if err != nil {
		log.Printf("[handler] add-chain: copy: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	vc, err := verifiable.ParseCredential(dest.Bytes(), verifiable.WithPublicKeyFetcher(
		verifiable.NewDIDKeyResolver(s.vdr).PublicKeyFetcher(),
	), verifiable.WithDisabledProofCheck())
	if err != nil {
		log.Printf("[handler] add-chain: parse credential: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	leaf := merkleTreeLeaf{
		Version:  v1,
		LeafType: timestampedEntryLeafType,
		TimestampedEntry: &timestampedEntry{
			EntryType:  vcLogEntryType,
			Timestamp:  uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			VCEntry:    vc,
			Extensions: nil,
		},
	}

	leafData, err := json.Marshal(leaf)
	if err != nil {
		log.Printf("[handler] add-chain: marshal: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	leafIDHash := sha256.Sum256(dest.Bytes())

	resp, err := s.client.QueueLeaf(context.Background(), &trillian.QueueLeafRequest{
		LogId: s.logID,
		Leaf: &trillian.LogLeaf{
			LeafValue:        leafData,
			LeafIdentityHash: leafIDHash[:],
		},
	})
	if err != nil {
		log.Printf("[handler] add-chain: add sequenced leaves: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	var loggedLeaf merkleTreeLeaf
	if err := json.Unmarshal(resp.QueuedLeaf.Leaf.LeafValue, &loggedLeaf); err != nil {
		log.Printf("[handler] add-chain: unmarshal: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
	}

	// TODO: add signature
	result := addChainResponse{
		SCTVersion: loggedLeaf.Version,
		Extensions: base64.StdEncoding.EncodeToString(leaf.TimestampedEntry.Extensions),
		Timestamp:  loggedLeaf.TimestampedEntry.Timestamp,
	}
	if err := json.NewEncoder(rw).Encode(result); err != nil {
		log.Printf("[handler] add-chain: json encode: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *service) getEntriesHandler(rw http.ResponseWriter, r *http.Request) {
	start, end, err := parseGetEntriesRange(r, 1000)
	if err != nil {
		log.Printf("[handler] get-entries: parse get entries range: %v", err)

		rw.WriteHeader(http.StatusBadRequest)

		return
	}

	count := end + 1 - start
	req := trillian.GetLeavesByRangeRequest{
		LogId:      s.logID,
		StartIndex: start,
		Count:      count,
	}

	rsp, err := s.client.GetLeavesByRange(context.Background(), &req)
	if err != nil {
		log.Printf("[handler] get-entries: get leaves by range: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	var currentRoot types.LogRootV1
	if err := currentRoot.UnmarshalBinary(rsp.GetSignedLogRoot().GetLogRoot()); err != nil {
		log.Printf("[handler] get-entries: unmarshal binary: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	resp := getEntriesResponse{}

	for _, leaf := range rsp.Leaves {
		resp.Entries = append(resp.Entries, leafEntry{
			LeafInput: leaf.LeafValue,
			ExtraData: leaf.ExtraData,
		})
	}

	if err := json.NewEncoder(rw).Encode(resp); err != nil {
		log.Printf("[handler] get-entries: json encode: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *service) getProofByHash(rw http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	if hash == "" {
		log.Println("[handler] get-proof-by-hash: empty hash")

		rw.WriteHeader(http.StatusBadRequest)

		return
	}

	leafHash, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		log.Printf("[handler] get-proof-by-hash: invalid base64 hash: %v", err)

		rw.WriteHeader(http.StatusBadRequest)

		return
	}

	treeSize, err := strconv.ParseInt(r.FormValue("tree_size"), 10, 64)
	if err != nil || treeSize < 1 {
		log.Println("[handler] get-proof-by-hash: missing or invalid tree_size")

		rw.WriteHeader(http.StatusBadRequest)

		return
	}

	req := trillian.GetInclusionProofByHashRequest{
		LogId:           s.logID,
		LeafHash:        leafHash,
		TreeSize:        treeSize,
		OrderBySequence: true,
	}

	rsp, err := s.client.GetInclusionProofByHash(context.Background(), &req)
	if err != nil {
		log.Printf("[handler] get-proof-by-hash: get inclusion proof by hash: %s", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	proofRsp := getProofByHashResponse{
		LeafIndex: rsp.Proof[0].LeafIndex,
		AuditPath: rsp.Proof[0].Hashes,
	}

	if err := json.NewEncoder(rw).Encode(proofRsp); err != nil {
		log.Printf("[handler] get-proof-by-hash: json encode: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *service) getRootsHandler(rw http.ResponseWriter, r *http.Request) {
	// TODO: needs to be implemented
}

func (s *service) getEntryAndProofHandler(rw http.ResponseWriter, r *http.Request) {
	leafIndex, treeSize, err := parseGetEntryAndProofParams(r)
	if err != nil {
		log.Printf("[handler] get-entry-and-proof: parse get entry and proof params: %v", err)

		rw.WriteHeader(http.StatusBadRequest)

		return
	}

	req := trillian.GetEntryAndProofRequest{
		LogId:     s.logID,
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
	}

	rsp, err := s.client.GetEntryAndProof(context.Background(), &req)
	if err != nil {
		log.Printf("[handler] get-entry-and-proof: get entry and proof: %v", err)

		rw.WriteHeader(http.StatusBadRequest)

		return
	}

	resp := getEntryAndProofResponse{
		LeafInput: rsp.Leaf.LeafValue,
		ExtraData: rsp.Leaf.ExtraData,
		AuditPath: rsp.Proof.Hashes,
	}

	if err := json.NewEncoder(rw).Encode(resp); err != nil {
		log.Printf("[handler] get-entry-and-proof: json encode: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
	}
}

func parseGetEntriesRange(r *http.Request, maxRange int64) (int64, int64, error) {
	start, err := strconv.ParseInt(r.FormValue("start"), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse int start value: %w", err)
	}

	end, err := strconv.ParseInt(r.FormValue("end"), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse int end value: %w", err)
	}

	if start < 0 || end < 0 {
		return 0, 0, fmt.Errorf("%w: start %d and end %d values must be >= 0", errValidation, start, end)
	}

	if start > end {
		return 0, 0, fmt.Errorf("%w: start %d and end %d values is not a valid range", errValidation, start, end)
	}

	if end-start+1 > maxRange {
		end = start + maxRange - 1
	}

	return start, end, nil
}

func parseGetEntryAndProofParams(r *http.Request) (int64, int64, error) {
	leafIndex, err := strconv.ParseInt(r.FormValue("leaf_index"), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: parameter leaf_index is not a number", errValidation)
	}

	treeSize, err := strconv.ParseInt(r.FormValue("tree_size"), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: parameter tree_size is not a number", errValidation)
	}

	if treeSize <= 0 {
		return 0, 0, fmt.Errorf("%w: tree_size must be greater than zero", errValidation)
	}

	if leafIndex < 0 {
		return 0, 0, fmt.Errorf("%w: leaf_index must be greater than or equal to zero", errValidation)
	}

	if leafIndex >= treeSize {
		return 0, 0, fmt.Errorf("%w: leaf_index must be less than tree_size", errValidation)
	}

	return leafIndex, treeSize, nil
}
