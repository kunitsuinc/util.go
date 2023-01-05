package jws

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/kunitsuinc/util.go/pkg/jose"
	"github.com/kunitsuinc/util.go/pkg/jose/jwt"
)

var ErrHeaderIsNil = errors.New("jws: header is nil")

func NewToken(header *jose.Header, payload *jwt.Claims, key crypto.PrivateKey) (token string, err error) {
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

	signature, err := Sign(header.Algorithm, headerEncoded+"."+payloadEncoded, key)
	if err != nil {
		return "", fmt.Errorf("jws.Sign: %w", err)
	}

	return headerEncoded + "." + payloadEncoded + "." + signature, nil
}
