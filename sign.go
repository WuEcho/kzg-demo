/**
 * Copyright 2024.1.11
 * @Author: EchoWu
 * @Description: This file is part of the MultiAdaptive library.
 */
package kzg_sdk

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	ErrInvalidSig     = errors.New("invalid fileData v, r, s values")
	ErrInvalidChainId = errors.New("invalid chain id for signer")
)

// SignDA signs the Data using the given signer and private key.
func SignDA(sender common.Address, index, length uint64, commitment kzg.Digest, signer DASigner, prv *ecdsa.PrivateKey) (common.Hash, []byte, error) {
	h := signer.Hash(sender, index, length, commitment)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return h, nil, err
	}
	if len(sig) == 0 {
		return h, nil, errors.New("sign is empty")
	}
	v := []byte{sig[64] + 27}
	newSig := sig[:64]
	newSig = append(newSig, v...)
	return h, newSig, nil
}

// DASender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
func DASender(signer DASigner, sig []byte, signHash common.Hash) (common.Address, error) {
	addr, err := signer.Sender(sig, signHash)
	if err != nil {
		return common.Address{}, err
	}
	return addr, nil
}

func DAGetSender(signer DASigner, sig []byte, sender common.Address, index, length uint64, commitment kzg.Digest) (common.Address, error) {
	h := signer.Hash(sender, index, length, commitment)
	addr, err := signer.Sender(sig, h)
	if err != nil {
		return common.Address{}, err
	}
	return addr, nil
}

// DASigner encapsulates fileData signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
//
// Note that this interface is not a stable API and may change at any time to accommodate
// new protocol rules.
type DASigner interface {
	// Sender returns the sender address of the fileData.
	Sender(sig []byte, signHash common.Hash) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(sig []byte) (r, s, v *big.Int, err error)

	ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the fileData hash that is signed by the
	// private key. This hash does not uniquely identify the fileData.
	Hash(sender common.Address, index, length uint64, commitment kzg.Digest) common.Hash

	// Equal returns true if the given signer is the same as the receiver.
	Equal(DASigner) bool
}

//var big8 = big.NewInt(8)

// EIP155Signer implements Signer using the EIP-155 rules. This accepts transactions which
// are replay-protected as well as unprotected homestead transactions.
type EIP155DASigner struct {
	chainId, chainIdMul *big.Int
}

func NewEIP155DASigner(chainId *big.Int) EIP155DASigner {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return EIP155DASigner{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s EIP155DASigner) ChainID() *big.Int {
	return s.chainId
}

func (s EIP155DASigner) Equal(s2 DASigner) bool {
	eip155, ok := s2.(EIP155DASigner)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

func (s EIP155DASigner) Sender(sig []byte, signHash common.Hash) (common.Address, error) {
	R, S, V := sliteSignature(sig)
	return recoverPlain(signHash, R, S, V, true)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s EIP155DASigner) SignatureValues(sig []byte) (R, S, V *big.Int, err error) {
	R, S, V = decodeSignature(sig)
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155DASigner) Hash(sender common.Address, index, length uint64, commitment kzg.Digest) common.Hash {
	data := make([]byte, 0)
	dt := uint64ToBigEndianHexBytes(s.chainId.Uint64())
	chainId := transTo32Byte(dt)
	indexByte := transTo32Byte(uint64ToBigEndianHexBytes(index))
	lengthByte := transTo32Byte(uint64ToBigEndianHexBytes(length))
	addrByte := transTo32Byte(sender.Bytes())
	commitXByte := commitment.X.Bytes()
	commitYByte := commitment.Y.Bytes()
	data = append(data, chainId[:]...)
	data = append(data, addrByte[:]...)
	data = append(data, indexByte[:]...)
	data = append(data, lengthByte[:]...)
	data = append(data, commitXByte[:]...)
	data = append(data, commitYByte[:]...)
	return crypto.Keccak256Hash(data)
}

// HomesteadDASigner implements Signer interface using the
// homestead rules.
type HomesteadDASigner struct{ FrontierDASigner }

func (s HomesteadDASigner) ChainID() *big.Int {
	return nil
}

func (s HomesteadDASigner) Equal(s2 DASigner) bool {
	_, ok := s2.(HomesteadDASigner)
	return ok
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (hs HomesteadDASigner) SignatureValues(sig []byte) (r, s, v *big.Int, err error) {
	return hs.FrontierDASigner.SignatureValues(sig)
}

func (hs HomesteadDASigner) Sender(sig []byte, signHash common.Hash) (common.Address, error) {
	r, s, v := decodeSignature(sig)
	v.Sub(v, new(big.Int).SetUint64(27))
	return recoverPlain(signHash, r, s, v, true)
}

// FrontierDASigner implements Signer interface using the
// frontier rules.
type FrontierDASigner struct{}

func (s FrontierDASigner) ChainID() *big.Int {
	return nil
}

func (s FrontierDASigner) Equal(s2 DASigner) bool {
	_, ok := s2.(FrontierDASigner)
	return ok
}

func (fs FrontierDASigner) Sender(sig []byte, signHash common.Hash) (common.Address, error) {
	r, s, v := sliteSignature(sig)
	v = v.Mul(v, new(big.Int).SetUint64(27))
	return recoverPlain(signHash, r, s, v, false)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (fs FrontierDASigner) SignatureValues(sig []byte) (r, s, v *big.Int, err error) {
	r, s, v = decodeSignature(sig)
	return r, s, v, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (fs FrontierDASigner) Hash(sender common.Address, index, length uint64, commitment kzg.Digest) common.Hash {
	data := make([]byte, 0)
	indexByte := transTo32Byte(uint64ToBigEndianHexBytes(index))
	lengthByte := transTo32Byte(uint64ToBigEndianHexBytes(length))
	addrByte := transTo32Byte(sender.Bytes())
	commitXByte := commitment.X.Bytes()
	commitYByte := commitment.Y.Bytes()
	data = append(data, addrByte[:]...)
	data = append(data, indexByte[:]...)
	data = append(data, lengthByte[:]...)
	data = append(data, commitXByte[:]...)
	data = append(data, commitYByte[:]...)
	return crypto.Keccak256Hash(data)
}

func decodeSignature(sig []byte) (r, s, v *big.Int) {
	if len(sig) != crypto.SignatureLength {
		panic(fmt.Sprintf("wrong size for signature: got %d, want %d", len(sig), crypto.SignatureLength))
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v
}

func sliteSignature(sig []byte) (r, s, v *big.Int) {
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes(sig[64:])
	return r, s, v
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int, homestead bool) (common.Address, error) {
	if Vb.BitLen() > 8 {
		return common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, homestead) {
		return common.Address{}, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}
