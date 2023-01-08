package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"hash"
)

func signHS(key any, signingInput string, hashNewFunc func() hash.Hash) (signatureEncoded string, err error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return "", ErrInvalidKeyReceived
	}
	h := hmac.New(hashNewFunc, keyBytes)
	h.Write([]byte(signingInput))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func signRS(key crypto.PrivateKey, signingInput string, hashNewFunc func() hash.Hash, cryptoHash crypto.Hash) (signatureEncoded string, err error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", ErrInvalidKeyReceived
	}

	h := hashNewFunc()
	h.Write([]byte(signingInput))
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, priv, cryptoHash, h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("rsa.SignPKCS1v15: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(rawSignature), nil
}

func signES(key crypto.PrivateKey, signingInput string, cryptoHash crypto.Hash, keySize int) (signatureEncoded string, err error) {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", ErrInvalidKeyReceived
	}

	h := cryptoHash.New()
	h.Write([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("ecdsa.Sign: %w", err)
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keySize)
	copy(rBytesPadded[keySize-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keySize)
	copy(sBytesPadded[keySize-len(sBytes):], sBytes)

	var rawSignature []byte
	rawSignature = append(rawSignature, rBytesPadded...)
	rawSignature = append(rawSignature, sBytesPadded...)

	return base64.RawURLEncoding.EncodeToString(rawSignature), nil
}

func signPS(key crypto.PrivateKey, signingInput string, cryptoHash crypto.Hash) (signatureEncoded string, err error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", ErrInvalidKeyReceived
	}

	h := cryptoHash.New()
	h.Write([]byte(signingInput))
	rawSignature, err := rsa.SignPSS(rand.Reader, priv, cryptoHash, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", fmt.Errorf("rsa.SignPSS: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(rawSignature), nil
}
