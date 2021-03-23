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
		NewHTTPHandler(addVCPath, http.MethodPost, c.addVC),
		NewHTTPHandler(getSTHPath, http.MethodGet, c.getSTH),
		NewHTTPHandler(getSTHConsistencyPath, http.MethodGet, c.GetSTHConsistency),
		NewHTTPHandler(getProofByHashPath, http.MethodGet, c.getProofByHash),
		NewHTTPHandler(getEntriesPath, http.MethodGet, c.getEntries),
		NewHTTPHandler(getIssuersPath, http.MethodGet, c.getIssuers),
		NewHTTPHandler(getEntryAndProofPath, http.MethodGet, c.getEntryAndProof),
	}
}

func (c *Operation) addVC(w http.ResponseWriter, r *http.Request) {
	execute(nil, w, r.Body)
}

func (c *Operation) getSTH(w http.ResponseWriter, r *http.Request) {
	execute(nil, w, r.Body)
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
		sendError(w, fmt.Errorf("marshal: %w", err))

		return
	}

	execute(c.cmd.GetSTHConsistency, w, bytes.NewBuffer(req))
}

func (c *Operation) getProofByHash(w http.ResponseWriter, r *http.Request) {
	execute(nil, w, r.Body)
}

func (c *Operation) getEntries(w http.ResponseWriter, r *http.Request) {
	execute(nil, w, r.Body)
}

func (c *Operation) getIssuers(w http.ResponseWriter, r *http.Request) {
	execute(nil, w, r.Body)
}

func (c *Operation) getEntryAndProof(w http.ResponseWriter, r *http.Request) {
	execute(nil, w, r.Body)
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
