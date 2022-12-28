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

type Verifier func() (*jws.Header, *Claims, error)

func (v Verifier) Verify() (*jws.Header, *Claims, error) {
	return v()
}

func JWSVerifier(
	token string,
	key any,
	claimsVerifier func(claims *Claims) error,
) Verifier {
	return func() (*jws.Header, *Claims, error) {
		header, payload, err := jws.VerifySignature(token, key)
		if err != nil {
			return nil, nil, err //nolint:wrapcheck
		}
		if claimsVerifier == nil {
			return nil, nil, err
		}
		claims := new(Claims)
		if err := claims.Decode(payload); err != nil {
			return nil, nil, err
		}
		if err := claimsVerifier(claims); err != nil {
			return nil, nil, err
		}
		return header, claims, nil
	}
}

func Verify(verifier Verifier) (*jws.Header, *Claims, error) {
	return verifier.Verify()
}
