package command

import (
	"fmt"

	"github.com/soluchok/witness-ledger/pkg/controller/errors"
)

// GetSTHConsistencyRequest represents the request to the get-sth-consistency.
type GetSTHConsistencyRequest struct {
	FirstTreeSize  int64
	SecondTreeSize int64
}

// Validate validates data.
func (r *GetSTHConsistencyRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: validate on nil value", errors.ErrValidation)
	}

	if r.FirstTreeSize < 0 || r.SecondTreeSize < 0 {
		return fmt.Errorf("%w: %d < 0 || %d < 0", errors.ErrValidation, r.FirstTreeSize, r.SecondTreeSize)
	}

	if r.SecondTreeSize < r.FirstTreeSize {
		return fmt.Errorf("%w: %d < %d", errors.ErrValidation, r.SecondTreeSize, r.FirstTreeSize)
	}

	return nil
}

// GetSTHConsistencyResponse represents the response to the get-sth-consistency.
type GetSTHConsistencyResponse struct {
	Consistency [][]byte `json:"consistency"`
}
