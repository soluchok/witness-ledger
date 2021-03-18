package main

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	io.Copy(dest, req.Body)

	resp, err := s.client.AddSequencedLeaves(context.Background(), &trillian.AddSequencedLeavesRequest{
		LogId: s.logID,
		Leaves: []*trillian.LogLeaf{{
			LeafIndex: s.index,
			LeafValue: dest.Bytes(),
			//ExtraData: []byte("extra"),
		}},
	})
	if err != nil {
		log.Printf("add handler: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.index++
	json.NewEncoder(rw).Encode(resp.Results)
}

func (s *service) getSthHandler(rw http.ResponseWriter, _ *http.Request) {
	resp, err := s.client.GetLatestSignedLogRoot(context.Background(), &trillian.GetLatestSignedLogRootRequest{
		LogId: s.logID,
	})
	if err != nil {
		log.Printf("get handler: %v", err)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	var currentRoot types.LogRootV1
	if err := currentRoot.UnmarshalBinary(resp.SignedLogRoot.GetLogRoot()); err != nil {
		log.Printf("failed to unmarshal root: %v", resp.SignedLogRoot)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if hashSize := len(currentRoot.RootHash); hashSize != sha256.Size {
		log.Printf("bad hash size from backend expecting: %d got %d", sha256.Size, hashSize)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	json.NewEncoder(rw).Encode(currentRoot)
}
