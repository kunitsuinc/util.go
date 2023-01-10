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

	if vo.aud != "" {
		if err := verifyAudience(cs, vo.aud); err != nil {
			return err
		}
	}

	if vo.verifyPrivateClaimsFunc != nil {
		if err := vo.verifyPrivateClaimsFunc(cs.PrivateClaims); err != nil {
			return err
		}
	}

	return nil
}

func verifyAudience(cs *ClaimsSet, aud string) error {
	for _, got := range cs.Audience {
		if aud == got {
			return nil
		}
	}
	return fmt.Errorf("want=%v got=%v: %w", aud, cs.Audience, ErrAudienceIsNotMatch)
}
