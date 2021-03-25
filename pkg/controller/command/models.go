package command

import (
	"fmt"

	"github.com/soluchok/witness-ledger/pkg/controller/errors"
)

// Version type definition.
type Version uint8

// Version constants.
const (
	V1 Version = 0
)

// HashAlgorithm type definition.
type HashAlgorithm string

// HashAlgorithm constants.
const (
	SHA256Hash HashAlgorithm = "SHA256"
)

// SignatureAlgorithm type definition.
type SignatureAlgorithm string

// SignatureAlgorithm constants.
const (
	ECDSASignature SignatureAlgorithm = "ECDSA"
)

// SignatureType differentiates signatures.
type SignatureType uint64

// SignatureType constants.
const (
	TreeHashSignatureJSONType SignatureType = 100
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

// GetSTHResponse represents the response to the get-sth.
type GetSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`
	Timestamp         uint64 `json:"timestamp"`
	SHA256RootHash    []byte `json:"sha256_root_hash"`
	TreeHeadSignature []byte `json:"tree_head_signature"`
}

// TreeHeadSignature keeps the data over which the signature in an STH is created.
type TreeHeadSignature struct {
	Version        Version
	SignatureType  SignatureType
	Timestamp      uint64
	TreeSize       uint64
	SHA256RootHash []byte
}

// SignatureAndHashAlgorithm provides information about the algorithm used for the signature.
type SignatureAndHashAlgorithm struct {
	Hash      HashAlgorithm
	Signature SignatureAlgorithm
}

// DigitallySigned provides information about a signature.
type DigitallySigned struct {
	Algorithm SignatureAndHashAlgorithm
	Signature []byte
}
