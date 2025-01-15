package groth16

import (
	"fmt"
	"math/big"

	"github.com/datachainlab/go-risc0-verifier/risc0"
)

// VerifyRISC0Seal verifies the RISC-Zero seal with the given parameters.
func VerifyRISC0Seal(params risc0.VerifierParameters, seal []byte, imageID [32]byte, journalDigest [32]byte) error {
	claimDigest := risc0.CalculateClaimDigest(imageID, journalDigest)
	return verifyIntegrity(params, seal, claimDigest)
}

// VerifyRISC0SealBySelector verifies the RISC-Zero seal with the parameters corresponding to the given selector.
func VerifyRISC0SealBySelector(selector [4]byte, seal []byte, imageID [32]byte, journalDigest [32]byte) error {
	params, ok := GetVerifierParameters(selector)
	if !ok {
		return fmt.Errorf("verifier parameters not found for selector: %x", selector)
	}
	return VerifyRISC0Seal(params, seal, imageID, journalDigest)
}

func verifyIntegrity(params risc0.VerifierParameters, seal []byte, claimDigest [32]byte) error {
	proof, err := decodeSeal(seal)
	if err != nil {
		return fmt.Errorf("failed to decode seal: %w", err)
	}

	control0, control1 := splitDigest(params.ControlRoot)
	claim0, claim1 := splitDigest(claimDigest)

	var pubSignals = make([]*big.Int, 5)
	pubSignals[0] = new(big.Int).SetBytes(control0[:])
	pubSignals[1] = new(big.Int).SetBytes(control1[:])
	pubSignals[2] = new(big.Int).SetBytes(claim0[:])
	pubSignals[3] = new(big.Int).SetBytes(claim1[:])
	pubSignals[4] = new(big.Int).SetBytes(reverseByteOrderUint256(params.BN254ControlID))
	return verifyGroth16(&_vk, *proof, pubSignals)
}
