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
	// https://github.com/risc0/risc0/blob/v2.0.0/risc0/circuit/recursion/src/control_id.rs#L39-L45
	risc0VerifierParameters["2.0"] = buildVerifierParameters(
		"539032186827b06719244873b17b2d4c122e2d02cfb1994fe958b2523b844576",
		"c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
	)
	// https://github.com/risc0/risc0/blob/v2.1.0/risc0/circuit/recursion/src/control_id.rs#L39-L45
	risc0VerifierParameters["2.1"] = buildVerifierParameters(
		"884389273e128b32475b334dec75ee619b77cb33d41c332021fe7e44c746ee60",
		"c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
	)
	// https://github.com/risc0/risc0/blob/v2.2.0/risc0/circuit/recursion/src/control_id.rs#L39-L45
	risc0VerifierParameters["2.2"] = buildVerifierParameters(
		"ce52bf56033842021af3cf6db8a50d1b7535c125a34f1a22c6fdcf002c5a1529",
		"c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
	)
	// https://github.com/risc0/risc0/blob/v2.3.2/risc0/circuit/recursion/src/control_id.rs#L39-L45
	risc0VerifierParameters["2.3"] = buildVerifierParameters(
		"ce52bf56033842021af3cf6db8a50d1b7535c125a34f1a22c6fdcf002c5a1529",
		"c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
	)
	// https://github.com/risc0/risc0/blob/v3.0.1/risc0/circuit/recursion/src/control_id.rs#L53-L59
	risc0VerifierParameters["3.0"] = buildVerifierParameters(
		"a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56",
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
