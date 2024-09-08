package kzg_sdk

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"os"
	//"github.com/ethereum/go-ethereum/common"
	//"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	//"github.com/ethereum/go-ethereum/crypto/secp256k1"
	//solsha3 "github.com/miguelmota/go-solidity-sha3"
)

const dChunkSize = 30
const dSrsSize = 1 << 20

var (
	executed      bool
	KzgSdk KZGSdk
)

type KZGSdk struct {
	srs *kzg.SRS
}

// NewKZGSdk 初始化sdk，可以设置srsSize=1 << 16
func GenerateSRSFile() error {
	quickSrs, err := kzg.NewSRS(ecc.NextPowerOfTwo(dSrsSize), big.NewInt(-1))
	if err != nil {
		fmt.Println("NewSRS failed, ", err)
		return err
	}
	file, err := os.Create("./srs")
	if err != nil {
		fmt.Println("create file failed, ", err)
		return err
	}
	defer file.Close()
	quickSrs.WriteTo(file)
	if err != nil {
		fmt.Println("write file failed, ", err)
		return err
	}
	return nil
}

// all user should load same srs file
func InitKZGSdk(srsPath string) (*KZGSdk, error) {
	if !executed {
		var newsrs kzg.SRS
		newsrs.Pk.G1 = make([]bn254.G1Affine, dSrsSize)
		if _, err := os.Stat(srsPath); err != nil {
			return nil, err
		}
		file, err := os.Open(srsPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		_, err = newsrs.ReadFrom(file)
		if err != nil {
			return nil, err
		}
		KzgSdk = KZGSdk{srs: &newsrs}
		return &KzgSdk, nil
	} else {
		return &KzgSdk, nil
	}
}

func (KzgSdkSdk *KZGSdk) VerifyCommitWithProof(commit []byte, proof []byte, claimedValue []byte) (bool, error) {
	var h bn254.G1Affine
	h.SetBytes(proof)
	var c fr.Element
	c.SetBytes(claimedValue)

	var prof kzg.OpeningProof
	prof.H = h
	prof.ClaimedValue = c

	point := common.BytesToHash(commit)
	var p fr.Element
	p.SetBytes(point[:])

	var digest kzg.Digest
	digest.SetBytes(commit)

	err := kzg.Verify(&digest, &prof, p, KzgSdkSdk.srs.Vk)
	if err != nil {
		return false, err
	} else {
		return true, nil
	}
}

func (KzgSdkSdk *KZGSdk) SRS() *kzg.SRS {
	return KzgSdkSdk.srs
}

func (KzgSdkSdk *KZGSdk) GenerateDataCommit(data []byte) (kzg.Digest, error) {
	poly := dataToPolynomial(data)
	digest, err := kzg.Commit(poly, KzgSdkSdk.srs.Pk)
	if err != nil {
		return kzg.Digest{}, err
	}
	return digest, nil
}

func (KzgSdkSdk *KZGSdk) GenerateDataCommitAndProof(data []byte) (kzg.Digest, kzg.OpeningProof, error) {
	poly := dataToPolynomial(data)
	digest, err := kzg.Commit(poly, KzgSdkSdk.srs.Pk)
	if err != nil {
		return kzg.Digest{}, kzg.OpeningProof{}, err
	}

	commitHash := common.BytesToHash(digest.Marshal())
	var openPoint fr.Element
	openPoint.SetBytes(commitHash[:])

	openingProof, err := kzg.Open(poly, openPoint, KzgSdkSdk.srs.Pk)
	if err != nil {
		return digest, kzg.OpeningProof{}, err
	}
	return digest, openingProof, nil
}

func (KzgSdkSdk *KZGSdk) DataToPolynomial(data []byte) []fr.Element {
	return dataToPolynomial(data)
}

func dataToPolynomial(data []byte) []fr.Element {
	chunks := chunkBytes(data, dChunkSize)
	chunksLen := len(chunks)

	ps := make([]fr.Element, chunksLen)
	for i, chunk := range chunks {
		ps[i].SetBytes(chunk)
	}
	return ps
}

func (KzgSdkSdk *KZGSdk) DataCommit(polynomials []fr.Element) (kzg.Digest, error) {
	digest, err := kzg.Commit(polynomials, KzgSdkSdk.srs.Pk)
	return digest, err
}

//func (KzgSdkSdk *KZGSdk) TxSign(key *ecdsa.PrivateKey, commitment kzg.Digest, addressA common.Address, addressB common.Address, data []byte) ([]byte, []byte) {
//	commitmentBytes := commitment.Bytes()
//	var mergedData []byte
//	mergedData = append(mergedData, commitmentBytes[:]...)
//	mergedData = append(mergedData, addressA.Bytes()...)
//	mergedData = append(mergedData, addressB.Bytes()...)
//	mergedData = append(mergedData, data...)
//
//	return sign(string(mergedData), key)
//}

func chunkBytes(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}

	return chunks
}

func keyGen() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)

	if err != nil {
		panic(err)
	}

	return key
}

//
//func sign(message string, key *ecdsa.PrivateKey) ([]byte, []byte) {
//	// Turn the message into a 32-byte hash
//	hash := solsha3.SoliditySHA3(solsha3.String(message))
//	// Prefix and then hash to mimic behavior of eth_sign
//	prefixed := solsha3.SoliditySHA3(solsha3.String("\x19Ethereum Signed Message:\n32"), solsha3.Bytes32(hash))
//	sig, err := secp256k1.Sign(prefixed, math.PaddedBigBytes(key.D, 32))
//	if err != nil {
//		panic(err)
//	}
//	return sig, prefixed
//}

func random1Polynomial(size int) []fr.Element {
	f := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		f[i].SetRandom()
	}
	return f
}

/*
func main() {
	fmt.Println("The steps to generate CD(commit data)")
	//sdk := NewKZGSdk(dSrsSize)
	fmt.Println("1. load SRS file to init KzgSdk SDK")
	sdk, err := InitKZGSdk(dSrsSize, "./srs")
	if err != nil {
		fmt.Println("InitKZGSdk failed")
		return
	}

	fmt.Println("2. prepare test data ")
	data := make([]byte, dChunkSize*17)
	for i := range data {
		data[i] = 1
	}

	fmt.Print("3. generate data commit")
	digest, err := sdk.GenerateDataCommit(data)
	if err != nil {
		fmt.Println("GenerateDataCommit failed")
		return
	}
	fmt.Println("commit data is:", digest.Bytes())
}
*/
