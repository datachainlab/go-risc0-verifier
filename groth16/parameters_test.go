package groth16

import (
	"encoding/hex"
	"testing"

	"github.com/datachainlab/go-risc0-verifier/risc0"
)

func TestCalculateSelector(t *testing.T) {
	var expected [4]byte
	bz, err := hex.DecodeString("50bd1769")
	if err != nil {
		t.Fatal(err)
	}
	copy(expected[:], bz)

	p, _ := risc0.FindVerifierParameters("1.1")
	actual := CalculateSelector(p)
	if actual != expected {
		t.Fatalf("expected: %x, actual: %x", expected, actual)
	}
}
