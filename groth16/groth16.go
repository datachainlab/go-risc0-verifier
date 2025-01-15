package groth16

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-rapidsnark/verifier/bn256"
)

const qString = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

// Q is the order of the integer field (Zq) that fits inside the SNARK.
var Q, _ = new(big.Int).SetString(qString, 10)

// verifyGroth16 performs the verification the Groth16 zkSNARK proofs
func verifyGroth16(vk *VK, proof ProofPairingData, inputs []*big.Int) error {
	if len(inputs)+1 != len(vk.IC) {
		return fmt.Errorf("len(inputs)+1 != len(vk.IC)")
	}
	vkX := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		if inputs[i].Cmp(Q) != -1 {
			return fmt.Errorf("input value is not in the fields")
		}
		vkX = new(bn256.G1).Add(vkX, new(bn256.G1).ScalarMult(vk.IC[i+1], inputs[i]))
	}
	vkX = new(bn256.G1).Add(vkX, vk.IC[0])

	g1 := []*bn256.G1{proof.A, new(bn256.G1).Neg(vk.Alpha), vkX.Neg(vkX), new(bn256.G1).Neg(proof.C)}
	g2 := []*bn256.G2{proof.B, vk.Beta, vk.Gamma, vk.Delta}

	res := bn256.PairingCheck(g1, g2)
	if !res {
		return fmt.Errorf("invalid proofs")
	}
	return nil
}
