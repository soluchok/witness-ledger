package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
)

const serverAddr = ":7777"

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
	defer conn.Close()

	srv := newService(trillian.NewTrillianLogClient(conn), logID)

	router := mux.NewRouter()
	router.HandleFunc("/ct/v1/add-pre-chain", srv.addPreChainHandler).Methods(http.MethodPost)
	router.HandleFunc("/ct/v1/get-sth", srv.getSthHandler).Methods(http.MethodGet)

	if err = http.ListenAndServe(serverAddr, router); err != nil {
		log.Fatal(err)
	}
}

type service struct {
	client trillian.TrillianLogClient
	logID  int64
	index  int64
}

func newService(client trillian.TrillianLogClient, logID int64) *service {
	return &service{client: client, logID: logID}
}

func (s *service) addPreChainHandler(rw http.ResponseWriter, req *http.Request) {
	var dest = &bytes.Buffer{}
	_, err := io.Copy(dest, req.Body)
	if err != nil {
		log.Printf("[handler] add-pre-chain: copy: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, err := s.client.QueueLeaf(context.Background(), &trillian.QueueLeafRequest{
		LogId: s.logID,
		Leaf: &trillian.LogLeaf{
			LeafValue: dest.Bytes(),
		},
	})
	if err != nil {
		log.Printf("[handler] add-pre-chain: add sequenced leaves: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.index++

	if err := json.NewEncoder(rw).Encode(resp.QueuedLeaf); err != nil {
		log.Printf("[handler] add-pre-chain: json encode: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
	}
}

type GetSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`           // Number of certs in the current tree
	Timestamp         uint64 `json:"timestamp"`           // Time that the tree was created
	SHA256RootHash    []byte `json:"sha256_root_hash"`    // Root hash of the tree
	TreeHeadSignature []byte `json:"tree_head_signature"` // Log signature for this STH
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
	resp := GetSTHResponse{
		TreeSize:       currentRoot.TreeSize,
		SHA256RootHash: currentRoot.RootHash,
		Timestamp:      uint64(currentRoot.TimestampNanos / 1000 / 1000),
	}

	if err := json.NewEncoder(rw).Encode(resp); err != nil {
		log.Printf("[handler] get-sth: json encode: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
	}
}
