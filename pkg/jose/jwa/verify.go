package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"fmt"
	"hash"
	"math/big"
)

func verifyHS(key any, signingInput string, signature string, hashNewFunc func() hash.Hash) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKeyReceived
	}
	h := hmac.New(hashNewFunc, keyBytes)
	h.Write([]byte(signingInput))
	if !hmac.Equal([]byte(signature), h.Sum(nil)) {
		return fmt.Errorf("hmac.Equal: %w", ErrFailedToVerifySignature)
	}
	return nil
}

func verifyRS(signature []byte, signingInput string, key crypto.PublicKey, hashNewFunc func() hash.Hash, cryptoHash crypto.Hash) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidKeyReceived
	}
	h := hashNewFunc()
	h.Write([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, cryptoHash, h.Sum(nil), signature); err != nil {
		return fmt.Errorf("rsa.VerifyPKCS1v15: %w", err)
	}
	return nil
}

func verifyES(signature []byte, signingInput string, key crypto.PublicKey, cryptoHash crypto.Hash, keySize int) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidKeyReceived
	}
	if len(signature) != keySize*2 {
		return fmt.Errorf("len(signature)=%d != keySize*2=%d: %w", len(signature), keySize*2, ErrInvalidKeyReceived)
	}
	h := cryptoHash.New()
	h.Write([]byte(signingInput))
	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])
	if !ecdsa.Verify(pub, h.Sum(nil), r, s) {
		return fmt.Errorf("ecdsa.Verify: %w", ErrFailedToVerifySignature)
	}
	return nil
}

func verifyPS(signature []byte, signingInput string, key crypto.PublicKey, hashNewFunc func() hash.Hash, cryptoHash crypto.Hash, opts *rsa.PSSOptions) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidKeyReceived
	}
	h := hashNewFunc()
	h.Write([]byte(signingInput))
	if err := rsa.VerifyPSS(pub, cryptoHash, h.Sum(nil), signature, opts); err != nil {
		return fmt.Errorf("rsa.VerifyPSS: %w", err)
	}
	return nil
}
