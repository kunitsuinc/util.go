package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/kunitsuinc/util.go/pkg/jose"
	"github.com/kunitsuinc/util.go/pkg/jose/jws"
)

var (
	ErrTokenIsExpired     = errors.New("jwt: token is expired")
	ErrTokenIsNotBefore   = errors.New("jwt: token is not before")
	ErrAudienceIsNotMatch = errors.New("jwt: audience is not match")
)

func New(key any, header *jose.Header, claimsSet *ClaimsSet) (token string, err error) {
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

type verifyOption struct {
	aud                     string
	verifyPrivateClaimsFunc func(privateClaims PrivateClaims) error
}

type VerifyOption func(*verifyOption)

func VerifyAudience(aud string) VerifyOption {
	return func(vo *verifyOption) {
		vo.aud = aud
	}
}

func VerifyPrivateClaims(verifyPrivateClaimsFunc func(privateClaims PrivateClaims) error) VerifyOption {
	return func(vo *verifyOption) {
		vo.verifyPrivateClaimsFunc = verifyPrivateClaimsFunc
	}
}

func Verify(keyOption jws.KeyOption, jwt string, opts ...VerifyOption) (header *jose.Header, claimsSet *ClaimsSet, err error) {
	vo := new(verifyOption)
	for _, opt := range opts {
		opt(vo)
	}

	_, payloadEncoded, _, err := jws.Parse(jwt)
	if err != nil {
		return nil, nil, fmt.Errorf("jws.Parse: %w", err)
	}

	cs := new(ClaimsSet)
	if err := cs.Decode(payloadEncoded); err != nil {
		return nil, nil, fmt.Errorf("(*jwt.ClaimsSet).Decode: %w", err)
	}

	if err := verifyClaimsSet(cs, vo, time.Now()); err != nil {
		return nil, nil, err
	}

	h, err := jws.Verify(keyOption, jwt)
	if err != nil {
		return nil, nil, fmt.Errorf("jws.Verify: %w", err)
	}

	return h, cs, nil
}

func verifyClaimsSet(cs *ClaimsSet, vo *verifyOption, now time.Time) error {
	if cs.ExpirationTime != 0 && cs.ExpirationTime <= now.Unix() {
		return fmt.Errorf("exp=%d <= now=%d: %w", cs.ExpirationTime, now.Unix(), ErrTokenIsExpired)
	}

	if cs.NotBefore != 0 && cs.NotBefore >= now.Unix() {
		return fmt.Errorf("nbf=%d >= now=%d: %w", cs.NotBefore, now.Unix(), ErrTokenIsExpired)
	}

	if vo.aud != "" && vo.aud != cs.Audience {
		return fmt.Errorf("want=%s got=%s: %w", vo.aud, cs.Audience, ErrAudienceIsNotMatch)
	}

	if vo.verifyPrivateClaimsFunc != nil {
		if err := vo.verifyPrivateClaimsFunc(cs.PrivateClaims); err != nil {
			return err
		}
	}

	return nil
}
