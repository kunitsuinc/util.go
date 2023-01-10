package jws

import "github.com/kunitsuinc/util.go/pkg/jose/jwa"

func Sign(alg string, key any, signingInput string) (signatureEncoded string, err error) {
	return jwa.JWS(alg).Sign(key, signingInput) //nolint:wrapcheck
}
