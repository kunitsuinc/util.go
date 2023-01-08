package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"hash"
	"math/big"
)

func verifyHS(key any, signingInput string, signatureEncoded string, hashNewFunc func() hash.Hash) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKeyReceived
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureEncoded)
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.DecodeString: %w", err)
	}
	h := hmac.New(hashNewFunc, keyBytes)
	h.Write([]byte(signingInput))
	if !hmac.Equal(signature, h.Sum(nil)) {
		return fmt.Errorf("hmac.Equal: %w", ErrFailedToVerifySignature)
	}
	return nil
}

func verifyRS(key crypto.PublicKey, signingInput string, signatureEncoded string, hashNewFunc func() hash.Hash, cryptoHash crypto.Hash) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidKeyReceived
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureEncoded)
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.DecodeString: %w", err)
	}
	h := hashNewFunc()
	h.Write([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, cryptoHash, h.Sum(nil), signature); err != nil {
		return fmt.Errorf("rsa.VerifyPKCS1v15: %w", err)
	}
	return nil
}

func verifyES(key crypto.PublicKey, signingInput string, signatureEncoded string, cryptoHash crypto.Hash, keySize int) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidKeyReceived
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureEncoded)
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.DecodeString: %w", err)
	}
	if len(signature) != keySize*2 {
		return fmt.Errorf("len(signature)=%d != keySize*2=%d: %w", len(signature), keySize*2, ErrFailedToVerifySignature)
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

func verifyPS(key crypto.PublicKey, signingInput string, signatureEncoded string, hashNewFunc func() hash.Hash, cryptoHash crypto.Hash, opts *rsa.PSSOptions) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidKeyReceived
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureEncoded)
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.DecodeString: %w", err)
	}
	h := hashNewFunc()
	h.Write([]byte(signingInput))
	if err := rsa.VerifyPSS(pub, cryptoHash, h.Sum(nil), signature, opts); err != nil {
		return fmt.Errorf("rsa.VerifyPSS: %w", err)
	}
	return nil
}
