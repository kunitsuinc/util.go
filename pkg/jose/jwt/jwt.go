package jwt

import "github.com/kunitsuinc/util.go/pkg/jose"

func NewJWSToken(key any, header *jose.Header, claimsSet *ClaimsSet) (token string, err error) {
	return Sign(key, header, claimsSet)
}
