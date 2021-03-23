package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/trillian"
	"github.com/google/trillian/types"

	"github.com/soluchok/witness-ledger/pkg/controller/errors"
)

const (
	getSTHConsistency = "getSTHConsistency"
)

// Cmd is a controller for commands.
type Cmd struct {
	logID  int64
	client trillian.TrillianLogClient
}

// New returns commands controller.
func New(client trillian.TrillianLogClient, logID int64) (*Cmd, error) {
	return &Cmd{client: client, logID: logID}, nil
}

// GetHandlers returns list of all commands supported by this controller.
func (c *Cmd) GetHandlers() []Handler {
	return []Handler{
		NewCmdHandler(getSTHConsistency, c.GetSTHConsistency),
	}
}

// GetSTHConsistency retrieves merkle consistency proofs between signed tree heads.
func (c *Cmd) GetSTHConsistency(w io.Writer, r io.Reader) error {
	var request *GetSTHConsistencyRequest

	if err := json.NewDecoder(r).Decode(&request); err != nil {
		return fmt.Errorf("decode STHConsistency request: %w", err)
	}

	if err := request.Validate(); err != nil {
		return fmt.Errorf("validate STHConsistency request: %w", err)
	}

	// TODO: if FirstTreeSize is zero rpc returns bad request (rpc error: code = InvalidArgument
	//  desc = GetConsistencyProofRequest.FirstTreeSize: 0, want > 0)
	//  Need to figure out what to return error or empty response (certificate-transparency-go uses empty response).
	if request.FirstTreeSize == 0 {
		return json.NewEncoder(w).Encode(GetSTHConsistencyResponse{})
	}

	req := trillian.GetConsistencyProofRequest{
		LogId:          c.logID,
		FirstTreeSize:  request.FirstTreeSize,
		SecondTreeSize: request.SecondTreeSize,
	}

	resp, err := c.client.GetConsistencyProof(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("get consistency proof: %w", err)
	}

	var root types.LogRootV1
	if err := root.UnmarshalBinary(resp.GetSignedLogRoot().GetLogRoot()); err != nil {
		return fmt.Errorf("%w: unmarshal binary: %v", errors.ErrInternal, resp.GetSignedLogRoot().GetLogRoot())
	}

	if root.TreeSize < uint64(request.SecondTreeSize) {
		return fmt.Errorf("%w: need tree size: %d for proof but only got: %d",
			errors.ErrValidation, request.SecondTreeSize, root.TreeSize,
		)
	}

	return json.NewEncoder(w).Encode(GetSTHConsistencyResponse{
		Consistency: resp.Proof.GetHashes(),
	})
}
