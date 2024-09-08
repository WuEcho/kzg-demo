package kzg_sdk

import (
	"encoding/binary"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)


// rlpHash encodes x and hashes the encoded bytes.
func rlpHash(x interface{}) (h common.Hash) {
	crypto.Keccak256Hash()
	return h
}

func uint64ToBigEndianHexBytes(value uint64) []byte {
	// 创建一个长度为 8 的字节切片
	byteData := make([]byte, 8)
	// 使用 binary.BigEndian.PutUint64 将 uint64 转换为大端字节序
	binary.BigEndian.PutUint64(byteData, value)
	return byteData
}

func transTo32Byte(data []byte) [32]byte {
	var byteData [32]byte
	byteDataLength := len(byteData)
	dataLength := len(data)
	for i,b := range data {
		byteData[byteDataLength-dataLength+i] = b
	}
	return byteData
}
