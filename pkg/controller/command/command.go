package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/soluchok/witness-ledger/pkg/controller/errors"
)

const (
	getSTH            = "getSTH"
	getSTHConsistency = "getSTHConsistency"
)

// Key holds info about a key that is using for signing.
type Key struct {
	ID   string
	Type kms.KeyType
	kh   interface{}
}

// Cmd is a controller for commands.
type Cmd struct {
	logID  int64
	key    Key
	client trillian.TrillianLogClient
	kms    kms.KeyManager
	crypto ariescrypto.Crypto
}

// New returns commands controller.
func New(client trillian.TrillianLogClient, manager kms.KeyManager, crypto ariescrypto.Crypto,
	logID int64, key Key) (*Cmd, error) {
	kh, err := manager.Get(key.ID)
	if err != nil {
		return nil, fmt.Errorf("kms get kh: %w", err)
	}

	key.kh = kh

	return &Cmd{
		client: client,
		logID:  logID,
		kms:    manager,
		key:    key,
		crypto: crypto,
	}, nil
}

// GetHandlers returns list of all commands supported by this controller.
func (c *Cmd) GetHandlers() []Handler {
	return []Handler{
		NewCmdHandler(getSTHConsistency, c.GetSTHConsistency),
		NewCmdHandler(getSTH, c.GetSTH),
	}
}

// GetSTH retrieves latest signed tree head.
func (c *Cmd) GetSTH(w io.Writer, _ io.Reader) error {
	req := trillian.GetLatestSignedLogRootRequest{LogId: c.logID}

	resp, err := c.client.GetLatestSignedLogRoot(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("get latest signed log root: %w", err)
	}

	if resp.GetSignedLogRoot() == nil {
		return errors.New("no signed log root returned")
	}

	var root types.LogRootV1
	if err = root.UnmarshalBinary(resp.SignedLogRoot.GetLogRoot()); err != nil {
		return fmt.Errorf("unmarshal binary: %w", err)
	}

	ths, err := c.signV1TreeHead(root)
	if err != nil {
		return fmt.Errorf("sign tree head (v1): %w", err)
	}

	treeHeadSignature, err := json.Marshal(ths)
	if err != nil {
		return fmt.Errorf("marshal DigitallySigned payload: %w", err)
	}

	return json.NewEncoder(w).Encode(GetSTHResponse{
		TreeSize:          root.TreeSize,
		SHA256RootHash:    root.RootHash,
		Timestamp:         root.TimestampNanos / uint64(time.Millisecond),
		TreeHeadSignature: treeHeadSignature,
	})
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

func (c *Cmd) signV1TreeHead(root types.LogRootV1) (DigitallySigned, error) {
	sthBytes, err := json.Marshal(TreeHeadSignature{
		Version:        V1,
		SignatureType:  TreeHashSignatureJSONType,
		Timestamp:      root.TimestampNanos / uint64(time.Millisecond),
		TreeSize:       root.TreeSize,
		SHA256RootHash: root.RootHash,
	})
	if err != nil {
		return DigitallySigned{}, fmt.Errorf("marshal TreeHeadSignature: %w", err)
	}

	signature, err := c.crypto.Sign(sthBytes, c.key.kh)
	if err != nil {
		return DigitallySigned{}, fmt.Errorf("sign TreeHeadSignature: %w", err)
	}

	alg, err := signatureAndHashAlgorithmByKeyType(c.key.Type)
	if err != nil {
		return DigitallySigned{}, fmt.Errorf("signature and hash algorithm: %w", err)
	}

	return DigitallySigned{
		Algorithm: *alg,
		Signature: signature,
	}, nil
}

// TODO: Need to support more keys.
func signatureAndHashAlgorithmByKeyType(keyType kms.KeyType) (*SignatureAndHashAlgorithm, error) {
	switch keyType { // nolint: exhaustive
	case kms.ECDSAP256TypeDER:
		return &SignatureAndHashAlgorithm{
			Hash:      SHA256Hash,
			Signature: ECDSASignature,
		}, nil
	case kms.ECDSAP256TypeIEEEP1363:
		return &SignatureAndHashAlgorithm{
			Hash:      SHA256Hash,
			Signature: ECDSASignature,
		}, nil
	default:
		return nil, fmt.Errorf("%w: key type %v is not supported", errors.ErrInternal, keyType)
	}
}
