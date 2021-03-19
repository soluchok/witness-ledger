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
	"google.golang.org/grpc"
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
	VCEntry    []byte
	Extensions []byte
}

type addChainResponse struct {
	SCTVersion version `json:"sct_version"`
	ID         []byte  `json:"id"`
	Timestamp  uint64  `json:"timestamp"`
	Extensions string  `json:"extensions"`
	Signature  []byte  `json:"signature"`
}

type getSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`
	Timestamp         uint64 `json:"timestamp"`
	SHA256RootHash    []byte `json:"sha256_root_hash"`
	TreeHeadSignature []byte `json:"tree_head_signature"`
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

var errValidation = errors.New("data is not valid")

func main() {
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

	conn, err := grpc.Dial(endpoint, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			log.Println(err)
		}
	}()

	srv := newService(trillian.NewTrillianLogClient(conn), logID)

	router := mux.NewRouter()
	router.HandleFunc("/ct/v1/add-chain", srv.addChainHandler).Methods(http.MethodPost)
	router.HandleFunc("/ct/v1/get-sth", srv.getSthHandler).Methods(http.MethodGet)
	router.HandleFunc("/ct/v1/get-sth-consistency", srv.getSthConsistencyHandler).Methods(http.MethodGet)
	router.HandleFunc("/ct/v1/get-proof-by-hash", srv.getProofByHash).Methods(http.MethodGet)
	router.HandleFunc("/ct/v1/get-entries", srv.getEntriesHandler).Methods(http.MethodGet)
	router.HandleFunc("/ct/v1/get-roots", srv.getRootsHandler).Methods(http.MethodGet)
	router.HandleFunc("/ct/v1/get-entry-and-proof", srv.getEntryAndProofHandler).Methods(http.MethodGet)

	if err = http.ListenAndServe(serverAddr, router); err != nil {
		log.Printf("listen and serve: %v", err)
	}
}

type service struct {
	client trillian.TrillianLogClient
	logID  int64
}

func newService(client trillian.TrillianLogClient, logID int64) *service {
	return &service{client: client, logID: logID}
}

func (s *service) addChainHandler(rw http.ResponseWriter, req *http.Request) { //nolint: funlen
	var dest bytes.Buffer

	_, err := io.Copy(&dest, req.Body)
	if err != nil {
		log.Printf("[handler] add-chain: copy: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	leaf := merkleTreeLeaf{
		Version:  v1,
		LeafType: timestampedEntryLeafType,
		TimestampedEntry: &timestampedEntry{
			EntryType:  vcLogEntryType,
			Timestamp:  uint64(time.Now().UnixNano() / int64(time.Millisecond)),
			VCEntry:    dest.Bytes(),
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

func (s *service) getSthHandler(rw http.ResponseWriter, _ *http.Request) {
	sth, err := s.client.GetLatestSignedLogRoot(context.Background(), &trillian.GetLatestSignedLogRootRequest{
		LogId: s.logID,
	})
	if err != nil {
		log.Printf("[handler] get-sth: get latest signed log root: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	var currentRoot types.LogRootV1
	if err := currentRoot.UnmarshalBinary(sth.SignedLogRoot.GetLogRoot()); err != nil {
		log.Printf("[handler] get-sth: unmarshal binary: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	// TODO: sign payload (TreeHeadSignature)
	resp := getSTHResponse{
		TreeSize:          currentRoot.TreeSize,
		SHA256RootHash:    currentRoot.RootHash,
		Timestamp:         currentRoot.TimestampNanos / uint64(time.Millisecond),
		TreeHeadSignature: nil,
	}

	if err := json.NewEncoder(rw).Encode(resp); err != nil {
		log.Printf("[handler] get-sth: json encode: %v", err)

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
	// Hash must be created like this base64.StdEncoding.EncodeToString(rfc6962.DefaultHasher.HashLeaf(leafData)))
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

func (s *service) getSthConsistencyHandler(rw http.ResponseWriter, r *http.Request) {
	// TODO: needs to be implemented
}

func (s *service) getRootsHandler(rw http.ResponseWriter, r *http.Request) {
	// TODO: needs to be implemented
}

func (s *service) getEntryAndProofHandler(rw http.ResponseWriter, r *http.Request) {
	// TODO: needs to be implemented
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
