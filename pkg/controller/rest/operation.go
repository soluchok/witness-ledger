package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/soluchok/witness-ledger/pkg/controller/command"
	"github.com/soluchok/witness-ledger/pkg/controller/errors"
)

var logger = log.New("controller/rest")

const (
	basePath              = "/ct/v1"
	addVCPath             = basePath + "/add-vc"
	getSTHPath            = basePath + "/get-sth"
	getSTHConsistencyPath = basePath + "/get-sth-consistency"
	getProofByHashPath    = basePath + "/get-proof-by-hash"
	getEntriesPath        = basePath + "/get-entries"
	getIssuersPath        = basePath + "/get-issuers"
	getEntryAndProofPath  = basePath + "/get-entry-and-proof"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
)

// Operation represents REST API controller.
type Operation struct {
	cmd *command.Cmd
}

// New returns REST API controller.
func New(cmd *command.Cmd) (*Operation, error) {
	return &Operation{cmd: cmd}, nil
}

// GetRESTHandlers returns list of all handlers supported by this controller.
func (c *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		NewHTTPHandler(addVCPath, http.MethodPost, c.AddVC),
		NewHTTPHandler(getSTHPath, http.MethodGet, c.GetSTH),
		NewHTTPHandler(getSTHConsistencyPath, http.MethodGet, c.GetSTHConsistency),
		NewHTTPHandler(getProofByHashPath, http.MethodGet, c.GetProofByHash),
		NewHTTPHandler(getEntriesPath, http.MethodGet, c.GetEntries),
		NewHTTPHandler(getIssuersPath, http.MethodGet, c.getIssuers),
		NewHTTPHandler(getEntryAndProofPath, http.MethodGet, c.GetEntryAndProof),
	}
}

// AddVC adds verifiable credential to log.
func (c *Operation) AddVC(w http.ResponseWriter, r *http.Request) {
	execute(c.cmd.AddVC, w, r.Body)
}

// GetSTH retrieves latest signed tree head.
func (c *Operation) GetSTH(w http.ResponseWriter, _ *http.Request) {
	execute(c.cmd.GetSTH, w, nil)
}

// GetSTHConsistency retrieves merkle consistency proofs between signed tree heads.
func (c *Operation) GetSTHConsistency(w http.ResponseWriter, r *http.Request) {
	const (
		firstParamName  = "first"
		secondParamName = "second"
	)

	first, err := strconv.ParseInt(r.FormValue(firstParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, firstParamName))

		return
	}

	second, err := strconv.ParseInt(r.FormValue(secondParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, secondParamName))

		return
	}

	req, err := json.Marshal(command.GetSTHConsistencyRequest{
		FirstTreeSize:  first,
		SecondTreeSize: second,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetSTHConsistency request: %w", err))

		return
	}

	execute(c.cmd.GetSTHConsistency, w, bytes.NewBuffer(req))
}

// GetProofByHash retrieves Merkle Audit proof from Log by leaf hash.
func (c *Operation) GetProofByHash(w http.ResponseWriter, r *http.Request) {
	const (
		hashParamName     = "hash"
		treeSizeParamName = "tree_size"
	)

	treeSize, err := strconv.ParseInt(r.FormValue(treeSizeParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, treeSizeParamName))

		return
	}

	req, err := json.Marshal(command.GetProofByHashRequest{
		Hash:     r.FormValue(hashParamName),
		TreeSize: treeSize,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetProofByHash request: %w", err))

		return
	}

	execute(c.cmd.GetProofByHash, w, bytes.NewBuffer(req))
}

// GetEntries retrieves entries from log.
func (c *Operation) GetEntries(w http.ResponseWriter, r *http.Request) {
	const (
		startParamName = "start"
		endParamName   = "end"
	)

	start, err := strconv.ParseInt(r.FormValue(startParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, startParamName))

		return
	}

	end, err := strconv.ParseInt(r.FormValue(endParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, endParamName))

		return
	}

	req, err := json.Marshal(command.GetEntriesRequest{
		Start: start,
		End:   end,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetEntries request: %w", err))

		return
	}

	execute(c.cmd.GetEntries, w, bytes.NewBuffer(req))
}

func (c *Operation) getIssuers(w http.ResponseWriter, r *http.Request) {
	execute(func(rw io.Writer, req io.Reader) error {
		return nil
	}, w, r.Body)
}

// GetEntryAndProof retrieves entry and merkle audit proof from log.
func (c *Operation) GetEntryAndProof(w http.ResponseWriter, r *http.Request) {
	const (
		leafIndexParamName = "leaf_index"
		treeSizeParamName  = "tree_size"
	)

	leafIndex, err := strconv.ParseInt(r.FormValue(leafIndexParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, leafIndexParamName))

		return
	}

	treeSize, err := strconv.ParseInt(r.FormValue(treeSizeParamName), 10, 64)
	if err != nil {
		sendError(w, fmt.Errorf("%w: parameter %q is not a number", errors.ErrValidation, treeSizeParamName))

		return
	}

	req, err := json.Marshal(command.GetEntryAndProofRequest{
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
	})
	if err != nil {
		sendError(w, fmt.Errorf("marshal GetEntryAndProof request: %w", err))

		return
	}

	execute(c.cmd.GetEntryAndProof, w, bytes.NewBuffer(req))
}

func execute(exec command.Exec, rw http.ResponseWriter, req io.Reader) {
	rw.Header().Set(contentType, applicationJSON)

	if err := exec(rw, req); err != nil {
		sendError(rw, err)
	}
}

func sendError(rw http.ResponseWriter, e error) {
	rw.WriteHeader(errors.StatusCodeFromError(e))

	if err := json.NewEncoder(rw).Encode(errorResponse{Message: e.Error()}); err != nil {
		logger.Errorf("send error response: %v", e)
	}
}
