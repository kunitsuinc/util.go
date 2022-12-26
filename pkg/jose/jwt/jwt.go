package jwt

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/kunitsuinc/util.go/pkg/jose/jws"
)

type Encoder func() (token string, err error)

func (e Encoder) Encode() (token string, err error) {
	return e()
}

var ErrHeaderIsNil = errors.New("jwt: header is nil")

func JWSEncoder(header *jws.Header, payload *Claims, key crypto.PrivateKey) Encoder {
	return func() (token string, err error) {
		if header == nil {
			return "", ErrHeaderIsNil
		}

		headerEncoded, err := header.Encode()
		if err != nil {
			return "", fmt.Errorf("(*jws.Header).Encode: %w", err)
		}

		payloadEncoded, err := payload.Encode()
		if err != nil {
			return "", fmt.Errorf("(*jwt.Claims).Encode: %w", err)
		}

		signature, err := jws.Sign(header.Algorithm, headerEncoded+"."+payloadEncoded, key)
		if err != nil {
			return "", fmt.Errorf("jws.Sign: %w", err)
		}

		return headerEncoded + "." + payloadEncoded + "." + signature, nil
	}
}

func New(encoder Encoder) (token string, err error) {
	return encoder.Encode()
}

type Verifier func() error

func (v Verifier) Verify() error {
	return v()
}

func JWSVerifier(
	token string,
	key any,
	headerVerifier func(header *jws.Header) error,
	claimsVerifier func(header *Claims) error,
) Verifier {
	return func() error {
		header, payload, err := jws.VerifySignature(token, key) //nolint:wrapcheck
		if err != nil {
			return err
		}
		if headerVerifier != nil {
			if err := headerVerifier(header); err != nil {
				return err
			}
		}
		if claimsVerifier != nil {
			claims := new(Claims)
			if err := claims.Decode(payload); err != nil {
				return err
			}
			if err := claimsVerifier(claims); err != nil {
				return err
			}
		}
		return nil
	}
}

func Verify(verifier Verifier) error {
	return verifier.Verify()
}
