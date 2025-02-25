package risc0

import "encoding/hex"

var (
	// version -> verifier parameters
	risc0VerifierParameters map[string]VerifierParameters
)

func init() {
	risc0VerifierParameters = make(map[string]VerifierParameters)
	// https://github.com/risc0/risc0/blob/v1.0.5/risc0/circuit/recursion/src/control_id.rs#L48-L54
	risc0VerifierParameters["1.0"] = buildVerifierParameters(
		"a516a057c9fbf5629106300934d48e0e775d4230e41e503347cad96fcbde7e2e",
		"51b54a62f2aa599aef768744c95de8c7d89bf716e11b1179f05d6cf0bcfeb60e",
	)
	// https://github.com/risc0/risc0/blob/v1.1.3/risc0/circuit/recursion/src/control_id.rs#L47-L52
	risc0VerifierParameters["1.1"] = buildVerifierParameters(
		"8b6dcf11d463ac455361b41fb3ed053febb817491bdea00fdb340e45013b852e",
		"4e160df1e119ac0e3d658755a9edf38c8feb307b34bc10b57f4538dbe122a005",
	)
	// https://github.com/risc0/risc0/blob/v1.2.0/risc0/circuit/recursion/src/control_id.rs#L47-L53
	risc0VerifierParameters["1.2"] = buildVerifierParameters(
		"8cdad9242664be3112aba377c5425a4df735eb1c6966472b561d2855932c0469",
		"c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
	)
	// https://github.com/risc0/risc0/blob/v1.3.0/risc0/circuit/recursion/src/control_id.rs#L49-L55
	risc0VerifierParameters["1.3"] = buildVerifierParameters(
		"6fcbfc564e08874a235c181e75bb53547402b116957f700497bf482e08060a15",
		"c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
	)
}

type VerifierParameters struct {
	ControlRoot    [32]byte
	BN254ControlID [32]byte
}

func buildVerifierParameters(controlRoot, bn254ControlID string) VerifierParameters {
	var controlRootBytes, bn254ControlIDBytes [32]byte
	bz, err := hex.DecodeString(controlRoot)
	if err != nil {
		panic(err)
	}
	copy(controlRootBytes[:], bz)
	bz, err = hex.DecodeString(bn254ControlID)
	if err != nil {
		panic(err)
	}
	copy(bn254ControlIDBytes[:], bz)
	return VerifierParameters{
		ControlRoot:    controlRootBytes,
		BN254ControlID: bn254ControlIDBytes,
	}
}

func GetVerifierParameters() map[string]VerifierParameters {
	return risc0VerifierParameters
}

func FindVerifierParameters(version string) (VerifierParameters, bool) {
	params, ok := risc0VerifierParameters[version]
	return params, ok
}
