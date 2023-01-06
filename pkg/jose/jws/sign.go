package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
)

func Sign(alg jwa.AlgorithmJWS, signingInput string, key any) (signature string, err error) { //nolint:funlen,cyclop
	// "alg" (Algorithm) Header Parameter Values for JWS - JSON Web Algorithms (JWA) ref. https://www.rfc-editor.org/rfc/rfc7518#section-3.1
	switch alg {
	case jwa.HS256:
		signature, err = signHS(signingInput, key, sha256.New)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.HS384:
		signature, err = signHS(signingInput, key, sha512.New384)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.HS512:
		signature, err = signHS(signingInput, key, sha512.New)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.RS256:
		signature, err = signRS(signingInput, key, sha256.New, crypto.SHA256)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.RS384:
		signature, err = signRS(signingInput, key, sha512.New384, crypto.SHA384)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.RS512:
		signature, err = signRS(signingInput, key, sha512.New, crypto.SHA512)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.ES256:
		signature, err = signES(signingInput, key, crypto.SHA256, 32)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.ES384:
		signature, err = signES(signingInput, key, crypto.SHA384, 48)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.ES512:
		signature, err = signES(signingInput, key, crypto.SHA512, 66)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.PS256:
		signature, err = signPS(signingInput, key, crypto.SHA256)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.PS384:
		signature, err = signPS(signingInput, key, crypto.SHA384)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.PS512:
		signature, err = signPS(signingInput, key, crypto.SHA512)
		if err != nil {
			return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, err)
		}
	case jwa.None:
		return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, ErrAlgorithmNoneIsNotSupported)
	default:
		return "", fmt.Errorf("alg=%s: key=%T: %w", alg, key, ErrInvalidAlgorithm)
	}

	return signature, nil
}

func signHS(signingInput string, key any, hashNewFunc func() hash.Hash) (signature string, err error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return "", ErrInvalidKeyReceived
	}
	h := hmac.New(hashNewFunc, keyBytes)
	h.Write([]byte(signingInput))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func signRS(signingInput string, key crypto.PrivateKey, hashNewFunc func() hash.Hash, cryptoHash crypto.Hash) (signature string, err error) {
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

func signES(signingInput string, key crypto.PrivateKey, cryptoHash crypto.Hash, keySize int) (signature string, err error) {
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

func signPS(signingInput string, key crypto.PrivateKey, cryptoHash crypto.Hash) (signature string, err error) {
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
