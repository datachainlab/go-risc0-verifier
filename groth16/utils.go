package groth16

import (
	"crypto"
	"encoding/binary"
	"math/big"
)

func parseBigInt(s string) [32]byte {
	var bi big.Int
	_, ok := bi.SetString(s, 10)
	if !ok {
		panic("failed to parse big.Int")
	}
	var u256 [32]byte
	copy(u256[:], bi.Bytes())
	return u256
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

func sha256Items(items ...[32]byte) []byte {
	var data []byte
	for _, item := range items {
		data = append(data, item[:]...)
	}
	return sha256Bytes(data)
}

func reverseByteOrderUint256(input [32]byte) []byte {
	var reversed [32]byte
	for i := 0; i < 32; i++ {
		reversed[i] = input[31-i]
	}
	return reversed[:]
}

func splitDigest(digest [32]byte) ([16]byte, [16]byte) {
	reversed := reverseByteOrderUint256(digest)

	var lower128, upper128 [16]byte
	copy(lower128[:], reversed[:16])
	copy(upper128[:], reversed[16:])

	return upper128, lower128
}

func taggedStruct(tagDigest [32]byte, down [][32]byte) [32]byte {
	downLen := uint16(len(down))
	var downLenLE [2]byte
	binary.BigEndian.PutUint16(
		downLenLE[:],
		uint16((downLen<<8)|(downLen>>8)),
	)
	downPacked := make([]byte, 0, len(down)*32)
	for _, d := range down {
		downPacked = append(downPacked, d[:]...)
	}
	return sha256(append(append(tagDigest[:], downPacked...), downLenLE[:]...))
}

func taggedListCons(tagDigest [32]byte, head, tail [32]byte) [32]byte {
	return taggedStruct(tagDigest, [][32]byte{head, tail})
}

func taggedList(tagDigest [32]byte, list [][32]byte) []byte {
	curr := [32]byte{}
	for i := 0; i < len(list); i++ {
		curr = taggedListCons(tagDigest, list[len(list)-1-i], curr)
	}
	return curr[:]
}

func concatBytes32(bzs ...[32]byte) []byte {
	var bz []byte
	for _, b := range bzs {
		bz = append(bz, b[:]...)
	}
	return bz
}
