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

func JWSEncoder(header *jws.Header, payload *ClaimsSet, key crypto.PrivateKey) Encoder {
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

type Verifier func() (*jws.Header, *ClaimsSet, error)

func (v Verifier) Verify() (*jws.Header, *ClaimsSet, error) {
	return v()
}

func JWSVerifier(
	token string,
	key any,
	claimsVerifier func(claims *ClaimsSet) error,
) Verifier {
	return func() (*jws.Header, *ClaimsSet, error) {
		header, payload, err := jws.VerifySignature(token, key)
		if err != nil {
			return nil, nil, err //nolint:wrapcheck
		}
		if claimsVerifier == nil {
			return nil, nil, err
		}
		claims := new(ClaimsSet)
		if err := claims.Decode(payload); err != nil {
			return nil, nil, err
		}
		if err := claimsVerifier(claims); err != nil {
			return nil, nil, err
		}
		return header, claims, nil
	}
}

func Verify(verifier Verifier) (*jws.Header, *ClaimsSet, error) {
	return verifier.Verify()
}

// NewBuilder().Build()

type JWT struct{}

func New2() JWT {
	return JWT{}
}

type JWS struct{}

func (j JWT) JWS() JWS {
	return JWS{}
}

func (j JWS) Build() (string, error) {
	return "", nil
}

type JWE struct{}

func (j JWT) JWE() JWE {
	return JWE{}
}

func (j JWE) Build() (string, error) {
	return "", nil
}

func _() {
	// header, claims, sign をどこで？
	New2().JWS().Build()
	New2().JWE().Build()

}

func Verify2() error {

}
