package groth16

import (
	"fmt"

	"github.com/iden3/go-rapidsnark/verifier/bn256"
)

// ProofPairingData describes three components of zkp proof in bn256 format.
type ProofPairingData struct {
	A *bn256.G1
	B *bn256.G2
	C *bn256.G1
}

func decodeSeal(seal []byte) (*ProofPairingData, error) {
	if len(seal) != 256 {
		return nil, fmt.Errorf("invalid seal length: %d", len(seal))
	}
	var aBz [64]byte
	copy(aBz[:32], seal[:32])
	copy(aBz[32:], seal[32:64])

	var bBz [128]byte
	copy(bBz[:32], seal[64:96])
	copy(bBz[32:64], seal[96:128])
	copy(bBz[64:96], seal[128:160])
	copy(bBz[96:], seal[160:192])

	var cBz [64]byte
	copy(cBz[:32], seal[192:224])
	copy(cBz[32:], seal[224:256])

	var (
		a, c bn256.G1
		b    bn256.G2
	)
	if _, err := a.Unmarshal(aBz[:]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal A: %w", err)
	}
	if _, err := b.Unmarshal(bBz[:]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal B: %w", err)
	}
	if _, err := c.Unmarshal(cBz[:]); err != nil {
		return nil, fmt.Errorf("failed to unmarshal C: %w", err)
	}
	return &ProofPairingData{
		A: &a,
		B: &b,
		C: &c,
	}, nil
}
