package kzg_sdk

import (
	"bytes"
	"crypto/sha256"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/stretchr/testify/assert"
)

const benchSize = 1 << 16

func BenchmarkSRSGen(b *testing.B) {

	b.Run("real SRS", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kzg.NewSRS(ecc.NextPowerOfTwo(benchSize), new(big.Int).SetInt64(42))
		}
	})
	b.Run("quick SRS", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kzg.NewSRS(ecc.NextPowerOfTwo(benchSize), big.NewInt(-1))
		}
	})
}

func BenchmarkKZGCommit(b *testing.B) {

	b.Run("real SRS", func(b *testing.B) {
		srs, err := kzg.NewSRS(ecc.NextPowerOfTwo(benchSize), new(big.Int).SetInt64(42))
		assert.NoError(b, err)
		// random polynomial
		p := randomPolynomial(benchSize / 2)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = kzg.Commit(p, srs.Pk)
		}
	})
	b.Run("quick SRS", func(b *testing.B) {
		srs, err := kzg.NewSRS(ecc.NextPowerOfTwo(benchSize), big.NewInt(-1))
		assert.NoError(b, err)
		// random polynomial
		p := randomPolynomial(benchSize / 2)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = kzg.Commit(p, srs.Pk)
		}
	})
}

//func BenchmarkDivideByXMinusA(b *testing.B) {
//	const pSize = 1 << 22
//
//	// build random polynomial
//	pol := make([]fr.Element, pSize)
//	pol[0].SetRandom()
//	for i := 1; i < pSize; i++ {
//		pol[i] = pol[i-1]
//	}
//	var a, fa fr.Element
//	a.SetRandom()
//	fa.SetRandom()
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		kzg.dividePolyByXminusA(pol, fa, a)
//		pol = pol[:pSize]
//		pol[pSize-1] = pol[0]
//	}
//}

func TestInitKZGSdk(t *testing.T) {
	index := 1
	s := strconv.Itoa(index)
	data := bytes.Repeat([]byte(s), 1024)

	d, err := InitKZGSdk("./srs")
	if err != nil {
		println("InitKZGSdk err", err.Error())
	}
	commit, err := d.GenerateDataCommit(data)
	if err != nil {
		println("GenerateDataCommit err", err.Error())
	}

	commitHex := common.Bytes2Hex(commit.Marshal())
	println("commitHex----", commitHex)

	commitHash := common.BytesToHash(commit.Marshal())
	println("commitHash-----", commitHash.String())

	var openPoint fr.Element
	openPoint.SetBytes(commitHash[:])

	poly := d.DataToPolynomial(data)

	openingProof, err := kzg.Open(poly, openPoint, d.SRS().Pk)
	if err != nil {
		println("kzg.Open----", err.Error())
	}

	hValue := openingProof.H.Marshal()

	claimedValue := openingProof.ClaimedValue.Marshal()

	flag, err := d.VerifyCommitWithProof(commit.Marshal(), hValue, claimedValue)
	if err != nil {
		println("d.VerifyCommitWithProof----", err, err.Error())
	}

	println("VerifyCommitWithProof----", flag)

	err = kzg.Verify(&commit, &openingProof, openPoint, d.SRS().Vk)
	if err != nil {
		println("kzg.Verify------", err.Error())
	}
}

func BenchmarkKZGOpen(b *testing.B) {
	srs, err := kzg.NewSRS(ecc.NextPowerOfTwo(benchSize), new(big.Int).SetInt64(42))
	assert.NoError(b, err)

	// random polynomial
	p := randomPolynomial(benchSize / 2)
	var r fr.Element
	r.SetRandom()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = kzg.Open(p, r, srs.Pk)
	}
}

func BenchmarkKZGVerify(b *testing.B) {
	srs, err := kzg.NewSRS(ecc.NextPowerOfTwo(benchSize), new(big.Int).SetInt64(42))
	assert.NoError(b, err)

	// random polynomial
	p := randomPolynomial(benchSize / 2)
	var r fr.Element
	r.SetRandom()

	// commit
	comm, err := kzg.Commit(p, srs.Pk)
	assert.NoError(b, err)

	// open
	openingProof, err := kzg.Open(p, r, srs.Pk)
	assert.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kzg.Verify(&comm, &openingProof, r, srs.Vk)
	}
}

func BenchmarkKZGBatchOpen10(b *testing.B) {
	srs, err := kzg.NewSRS(ecc.NextPowerOfTwo(benchSize), new(big.Int).SetInt64(42))
	assert.NoError(b, err)

	// 10 random polynomials
	var ps [10][]fr.Element
	for i := 0; i < 10; i++ {
		ps[i] = randomPolynomial(benchSize / 2)
	}

	// commitments
	var commitments [10]kzg.Digest
	for i := 0; i < 10; i++ {
		commitments[i], _ = kzg.Commit(ps[i], srs.Pk)
	}

	// pick a hash function
	hf := sha256.New()

	var r fr.Element
	r.SetRandom()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kzg.BatchOpenSinglePoint(ps[:], commitments[:], r, hf, srs.Pk)
	}
}

func BenchmarkKZGBatchVerify10(b *testing.B) {
	srs, err := kzg.NewSRS(ecc.NextPowerOfTwo(benchSize), new(big.Int).SetInt64(42))
	if err != nil {
		b.Fatal(err)
	}

	// 10 random polynomials
	var ps [10][]fr.Element
	for i := 0; i < 10; i++ {
		ps[i] = randomPolynomial(benchSize / 2)
	}

	// commitments
	var commitments [10]kzg.Digest
	for i := 0; i < 10; i++ {
		commitments[i], _ = kzg.Commit(ps[i], srs.Pk)
	}

	// pick a hash function
	hf := sha256.New()

	var r fr.Element
	r.SetRandom()

	proof, err := kzg.BatchOpenSinglePoint(ps[:], commitments[:], r, hf, srs.Pk)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kzg.BatchVerifySinglePoint(commitments[:], &proof, r, hf, srs.Vk)
	}
}

func randomPolynomial(size int) []fr.Element {
	f := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		f[i].SetRandom()
	}
	return f
}
