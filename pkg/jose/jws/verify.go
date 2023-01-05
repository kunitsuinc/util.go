package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"

	"github.com/kunitsuinc/util.go/pkg/jose"
	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
)

var (
	ErrInvalidTokenReceived        = errors.New(`jws: invalid token received, token must have 3 parts`)
	ErrAlgorithmNoneIsNotSupported = errors.New(`jws: algorithm "none" is not supported`)
	ErrInvalidKeyReceived          = errors.New(`jws: invalid key received`)
	ErrFailedToVerifySignature     = errors.New(`jws: failed to verify signature`)
	ErrInvalidAlgorithm            = errors.New(`jws: invalid algorithm`)
)

func VerifySignature(jwt string, key any) error { //nolint:funlen,cyclop
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ErrInvalidTokenReceived
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid jose header: %w", err)
	}

	header := new(jose.Header)
	if err := json.Unmarshal(headerJSON, header); err != nil {
		return fmt.Errorf("invalid jose header: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// "alg" (Algorithm) Header Parameter Values for JWS - JSON Web Algorithms (JWA) ref. https://www.rfc-editor.org/rfc/rfc7518#section-3.1
	switch header.Algorithm {
	case jwa.HS256:
		if err := verifyHS(signature, signingInput, key, sha256.New); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.HS384:
		if err := verifyHS(signature, signingInput, key, sha512.New384); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.HS512:
		if err := verifyHS(signature, signingInput, key, sha512.New); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.RS256:
		if err := verifyRS(signature, signingInput, key, sha256.New, crypto.SHA256); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.RS384:
		if err := verifyRS(signature, signingInput, key, sha512.New384, crypto.SHA384); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.RS512:
		if err := verifyRS(signature, signingInput, key, sha512.New, crypto.SHA512); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.ES256:
		if err := verifyES(signature, signingInput, key, crypto.SHA256, 32); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.ES384:
		if err := verifyES(signature, signingInput, key, crypto.SHA384, 48); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.ES512:
		if err := verifyES(signature, signingInput, key, crypto.SHA512, 66); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.PS256:
		if err := verifyPS(signature, signingInput, key, sha256.New, crypto.SHA256, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.PS384:
		if err := verifyPS(signature, signingInput, key, sha512.New384, crypto.SHA384, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.PS512:
		if err := verifyPS(signature, signingInput, key, sha512.New, crypto.SHA512, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, err)
		}
	case jwa.None:
		return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, ErrAlgorithmNoneIsNotSupported)
	default:
		return fmt.Errorf("alg=%s: key=%T: %w", header.Algorithm, key, ErrInvalidAlgorithm)
	}

	return nil
}

func verifyHS(signature []byte, signingInput string, key any, hashNewFunc func() hash.Hash) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKeyReceived
	}
	h := hmac.New(hashNewFunc, keyBytes)
	h.Write([]byte(signingInput))
	if !hmac.Equal(signature, h.Sum(nil)) {
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
