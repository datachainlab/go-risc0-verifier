package mock

import (
	"bytes"
	"fmt"

	"github.com/datachainlab/go-risc0-verifier/risc0"
)

var MockSelector [4]byte = [4]byte{0, 0, 0, 0}

// VerifyMockSeal verifies the mock seal with the given parameters.
func VerifyMockSeal(seal []byte, imageID [32]byte, journalDigest [32]byte) error {
	claimDigest := risc0.CalculateClaimDigest(imageID, journalDigest)
	if !bytes.Equal(seal, claimDigest[:]) {
		return fmt.Errorf("verification failed: %x != %x", seal, claimDigest)
	}
	return nil
}

// VerifyMockSealBySelector verifies the mock seal with the parameters corresponding to the given selector.
func VerifyMockSealBySelector(selector [4]byte, seal []byte, imageID [32]byte, journalDigest [32]byte) error {
	if selector != MockSelector {
		return fmt.Errorf("selector mismatch: %x != %x", selector, MockSelector)
	}
	return VerifyMockSeal(seal, imageID, journalDigest)
}

// MockProve returns the mock proof for the given imageID and journalDigest.
func MockProve(imageID [32]byte, journalDigest [32]byte) [32]byte {
	return risc0.CalculateClaimDigest(imageID, journalDigest)
}
