package risc0

import (
	"crypto"
	"encoding/binary"
	"encoding/hex"
)

var systemStateZeroDigest = getSystemStateZeroDigest()

func getSystemStateZeroDigest() [32]byte {
	digest, err := hex.DecodeString("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2")
	if err != nil {
		panic(err)
	}
	var bz [32]byte
	copy(bz[:], digest)
	return bz
}

func CalculateClaimDigest(imageID [32]byte, journalDigest [32]byte) [32]byte {
	return GetOKReceiptClaim(systemStateZeroDigest, imageID, journalDigest).Digest()
}

// Public claims about a zkVM guest execution, such as the journal committed to by the guest.
type ReceiptClaim struct {
	PreStateDigest  [32]byte
	PostStateDigest [32]byte
	ExitCode        ExitCode
	Input           [32]byte
	Output          [32]byte
}

func (rc ReceiptClaim) Digest() [32]byte {
	var data [170]byte
	copy(data[:32], sha256Bytes([]byte("risc0.ReceiptClaim")))
	copy(data[32:64], rc.Input[:])
	copy(data[64:96], rc.PreStateDigest[:])
	copy(data[96:128], rc.PostStateDigest[:])
	copy(data[128:160], rc.Output[:])
	binary.BigEndian.PutUint32(data[160:164], uint32(rc.ExitCode.System)<<24)
	binary.BigEndian.PutUint32(data[164:168], uint32(rc.ExitCode.User)<<24)
	copy(data[168:], []byte{0x04, 0x00})
	return sha256(data[:])
}

// ExitCode is the exit condition indicated by the zkVM at the end of the guest execution
type ExitCode struct {
	System SystemExitCode
	User   uint8
}

// Exit condition indicated by the zkVM at the end of the execution covered by this proof.
type SystemExitCode uint8

const (
	// `Halted` indicates normal termination of a program with an interior exit code returned from the
	// guest program. A halted program cannot be resumed.
	Halted SystemExitCode = iota
	// `Paused` indicates the execution ended in a paused state with an interior exit code set by the
	// guest program. A paused program can be resumed such that execution picks up where it left
	// of, with the same memory state.
	Paused
	// `SystemSplit` indicates the execution ended on a host-initiated system split. System split is
	// mechanism by which the host can temporarily stop execution of the execution ended in a system
	// split has no output and no conclusions can be drawn about whether the program will eventually
	// halt. System split is used in continuations to split execution into individually provable segments.
	SystemSplit
)

func GetOKReceiptClaim(systemStateZeroDigest, imageId, journalDigest [32]byte) ReceiptClaim {
	return ReceiptClaim{
		PreStateDigest:  imageId,
		PostStateDigest: systemStateZeroDigest,
		ExitCode: ExitCode{
			System: Halted,
			User:   0,
		},
		Input: [32]byte{},
		Output: Output{
			JournalDigest:     journalDigest,
			AssumptionsDigest: [32]byte{},
		}.Digest(),
	}
}

// Output field in the `ReceiptClaim`, committing to a claimed journal and assumptions list.
type Output struct {
	JournalDigest     [32]byte
	AssumptionsDigest [32]byte
}

func (o Output) Digest() [32]byte {
	var data [98]byte
	copy(data[:32], sha256Bytes([]byte("risc0.Output")))
	copy(data[32:64], o.JournalDigest[:])
	copy(data[64:96], o.AssumptionsDigest[:])
	copy(data[96:], []byte{0x02, 0x00})
	return sha256(data[:])
}

func sha256(input []byte) [32]byte {
	var hash [32]byte
	var h = crypto.SHA256.New()
	h.Write(input)
	copy(hash[:], h.Sum(nil))
	return hash
}

func sha256Bytes(input []byte) []byte {
	h := sha256(input)
	return h[:]
}
