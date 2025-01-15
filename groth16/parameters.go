package groth16

import "github.com/datachainlab/go-risc0-verifier/risc0"

// selector -> verifier parameters
var risc0SelectorVerifierParameters map[[4]byte]risc0.VerifierParameters

func init() {
	verifierParams := risc0.GetVerifierParameters()
	risc0SelectorVerifierParameters = make(map[[4]byte]risc0.VerifierParameters)
	for _, params := range verifierParams {
		selector := CalculateSelector(params)
		risc0SelectorVerifierParameters[selector] = params
	}
}

// CalculateSelector calculates the selector from the verifier parameters.
func CalculateSelector(params risc0.VerifierParameters) [4]byte {
	var data [130]byte
	copy(data[:32], sha256Bytes([]byte("risc0.Groth16ReceiptVerifierParameters")))
	copy(data[32:64], params.ControlRoot[:])
	copy(data[64:96], params.BN254ControlID[:])
	copy(data[96:128], vkDigest[:])
	copy(data[128:], []byte{0x03, 0x00})
	h := sha256(data[:])
	var selector [4]byte
	copy(selector[:], h[:4])
	return selector
}

// GetVerifierParameters returns the verifier parameters corresponding to the given selector.
func GetVerifierParameters(selector [4]byte) (risc0.VerifierParameters, bool) {
	params, ok := risc0SelectorVerifierParameters[selector]
	return params, ok
}

// GetVerifierParameters2 returns the verifier parameters corresponding to the given selector.
func GetVerifierParameters2(selector []byte) (risc0.VerifierParameters, bool) {
	var s [4]byte
	copy(s[:], selector)
	return GetVerifierParameters(s)
}
