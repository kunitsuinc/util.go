package jws

// var ErrHeaderIsNil = errors.New("jws: header is nil")

// func NewToken(header *jose.Header, payload *jwt.ClaimsSet, key crypto.PrivateKey) (token string, err error) {
// 	if header == nil {
// 		return "", ErrHeaderIsNil
// 	}

// 	headerEncoded, err := header.Encode()
// 	if err != nil {
// 		return "", fmt.Errorf("(*jws.Header).Encode: %w", err)
// 	}

// 	payloadEncoded, err := payload.Encode()
// 	if err != nil {
// 		return "", fmt.Errorf("(*jwt.Claims).Encode: %w", err)
// 	}

// 	signature, err := Sign(header.Algorithm, key, headerEncoded+"."+payloadEncoded)
// 	if err != nil {
// 		return "", fmt.Errorf("jws.Sign: %w", err)
// 	}

// 	return headerEncoded + "." + payloadEncoded + "." + signature, nil
// }
