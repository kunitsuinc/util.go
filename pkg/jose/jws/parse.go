package jws

import "strings"

func Parse(jwt string) (headerEncoded, payloadEncoded, signatureEncoded string, err error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", "", "", ErrInvalidTokenReceived
	}

	return parts[0], parts[1], parts[2], nil
}
