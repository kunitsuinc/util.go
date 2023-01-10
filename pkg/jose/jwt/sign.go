package jwt

import (
	"fmt"

	"github.com/kunitsuinc/util.go/pkg/jose"
	"github.com/kunitsuinc/util.go/pkg/jose/jws"
)

func Sign(key any, header *jose.Header, claimsSet *ClaimsSet) (token string, err error) {
	headerEncoded, err := header.Encode()
	if err != nil {
		return "", fmt.Errorf("(*jose.Header).Encode: %w", err)
	}

	claimsSetEncoded, err := claimsSet.Encode()
	if err != nil {
		return "", fmt.Errorf("(*jwt.ClaimsSet).Encode: %w", err)
	}

	signingInput := headerEncoded + "." + claimsSetEncoded
	signatureEncoded, err := jws.Sign(header.Algorithm, key, signingInput)
	if err != nil {
		return "", fmt.Errorf("jws.Sign: %w", err)
	}

	return signingInput + "." + signatureEncoded, nil
}
