package groth16

import (
	"encoding/hex"
	"testing"
)

func TestVerifyIntegrity(t *testing.T) {
	claimDigest_, err := hex.DecodeString("9cbe0c90f193cb5e5716c6bc1a780f164ca05254b8bd50485109d9d29544ea33")
	if err != nil {
		t.Fatal(err)
	}
	seal, err := hex.DecodeString("50bd1769188540e643a5e4b1548e4c9391b0359afc1488d25fbfe41395e8847079f64d55148c07b36f0d2d44bfbdcdbe9fc79b48062a75dec02bbd5bfd5e3e530f8fa1520a5f1d99b7cf0bd29b0dbdb4fa65186559593e2c415f1e8ce27ab302cacc917a1db4a97e49f4d82194363c3af262c3b0bcf57fe846130012d081cc8c1fc0337d0de1958f4e4c5755815559104d7576a3bfc0f5fffdb630eace4cc76a5f3b617210692dedcde61b1e581a1700476ae51fa573e0adc0405dcef88e6b902f1364be01080d0fbc1429093d77b320405ff81037e7d1ba6e029baa155b71283e10cbee1e6f5375ed061c83c8ce7e3123774ce8debfd9e90e34c95429eda72d688594b1")
	if err != nil {
		t.Fatal(err)
	}
	var claimDigest [32]byte
	copy(claimDigest[:], claimDigest_)
	p, ok := GetVerifierParameters2(seal[:4])
	if !ok {
		t.Fatal("GetVerifierParameters2 failed")
	}
	err = verifyIntegrity(p, seal[4:], claimDigest)
	if err != nil {
		t.Fatal(err)
	}
}
