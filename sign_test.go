package kzg_sdk

import (
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"testing"
)

func TestEIP155DASigner_Hash(t *testing.T) {
	addr := common.HexToAddress("0x1ca0a16a5a6b329a61bb3c8af4bd9f5abd892af8")
	signer := NewEIP155DASigner(big.NewInt(11155111))
	index := 0
	length := 1024
	var digest kzg.Digest
	str, _ := hex.DecodeString("0a30d8c5446284a8fa131a62eb44539355c4a56dd3272de812cec46d222947c11d05b4f0ee8da561dc2f2b7da17c4feeee2029f832a922884c02c3c9f1ca77c1")
	digest.SetBytes(str)
	hash := signer.Hash(addr,uint64(index),uint64(length),digest)
	println("hash-----",hash.String())
}


func BenchmarkVeriftSign(b *testing.B) {
	b.Run("verify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			signHash := common.HexToHash("0x194adeeafdb655b2da6c141abdcae1e908ed49c6986e45d72c3ca83658cd9721")
			signData,_ := hex.DecodeString("d02ee277524e10f0f59300bb60b7167ca741b37d85ad49b20ef13f782c35110d7d7898f13b27d649af86d28ca87df08ff8d8ca90d83863ea0a63f6a095145f291c")
			sender := common.HexToAddress("0x72B331Cde50eF0E183E007BB1050FF4b18aF59c1")
			signer := NewEIP155DASigner(big.NewInt(11))
			from, err := DASender(signer,signData,signHash)
			if err != nil {
				println("err----",err.Error())
			}

			if from != sender {
				println("error-----notcorrect",i)
			}
		}
	})

}