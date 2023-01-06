package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

//   - ref. JOSE Header - JSON Web Token (JWT) https://www.rfc-editor.org/rfc/rfc7519#section-5

// ClaimsSet
//
//   - ref. JWT Claims - JSON Web Token (JWT) https://www.rfc-editor.org/rfc/rfc7519#section-4
type ClaimsSet struct {
	// Issuer
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// Subject
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// Audience
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
	Audience string `json:"aud,omitempty"`

	// ExpirationTime
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
	ExpirationTime int64 `json:"exp,omitempty"`

	// NotBefore
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
	NotBefore int64 `json:"nbf,omitempty"`

	// IssuedAt
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6
	IssuedAt int64 `json:"iat,omitempty"`

	// JWTID
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7
	JWTID string `json:"jti,omitempty"`

	// PrivateClaims
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.3
	PrivateClaims PrivateClaims `json:"-"`
}

type PrivateClaims map[string]any

type Claims func(c *ClaimsSet)

func WithIssuer(iss string) Claims {
	return func(c *ClaimsSet) {
		c.Issuer = iss
	}
}

func WithSubject(sub string) Claims {
	return func(c *ClaimsSet) {
		c.Subject = sub
	}
}

func WithAudience(aud string) Claims {
	return func(c *ClaimsSet) {
		c.Audience = aud
	}
}

func WithExpirationTime(exp time.Time) Claims {
	return func(c *ClaimsSet) {
		c.ExpirationTime = exp.Unix()
	}
}

func WithNotBefore(nbf time.Time) Claims {
	return func(c *ClaimsSet) {
		c.NotBefore = nbf.Unix()
	}
}

func WithIssuedAt(iat time.Time) Claims {
	return func(c *ClaimsSet) {
		c.IssuedAt = iat.Unix()
	}
}

func WithJWTID(jti string) Claims {
	return func(c *ClaimsSet) {
		c.JWTID = jti
	}
}

func WithPrivateClaim(name string, value any) Claims {
	return func(c *ClaimsSet) {
		c.PrivateClaims[name] = value
	}
}

// NewClaimsSet
//
// Example:
//
//	header := jwt.NewClaimsSet(
//		jwt.WithIssuer("https://myapp.com"),
//		jwt.WithSubject("userID"),
//		jwt.WithExpirationTime(time.Now().Add(1*time.Hour)),
//	)
func NewClaimsSet(claims ...Claims) *ClaimsSet {
	c := &ClaimsSet{
		IssuedAt:      time.Now().Unix(),
		PrivateClaims: make(PrivateClaims),
	}

	for _, claim := range claims {
		claim(c)
	}

	return c
}

var ErrInvalidJSON = errors.New("jwt: invalid JSON")

func (c *ClaimsSet) UnmarshalJSON(data []byte) (err error) {
	// avoid recursion
	type _Claims ClaimsSet
	_claims := _Claims{}

	err = json.Unmarshal(data, &_claims)
	if err == nil {
		*c = ClaimsSet(_claims)
	}

	privateClaims := make(map[string]any)

	err = json.Unmarshal(data, &privateClaims)
	if err == nil {
		typ := reflect.TypeOf(_claims)
		for i := 0; i < typ.NumField(); i++ {
			delete(privateClaims, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}

		c.PrivateClaims = privateClaims
	}

	return err //nolint:wrapcheck
}

func (c *ClaimsSet) MarshalJSON() (data []byte, err error) {
	return c.marshalJSON(json.Marshal, bytes.HasSuffix, bytes.HasPrefix)
}

func (c *ClaimsSet) marshalJSON(
	json_Marshal func(v any) ([]byte, error), //nolint:revive,stylecheck
	bytes_HasSuffix func(s []byte, suffix []byte) bool, //nolint:revive,stylecheck
	bytes_HasPrefix func(s []byte, prefix []byte) bool, //nolint:revive,stylecheck
) (data []byte, err error) {
	// avoid recursion
	type _ClaimsSet ClaimsSet
	_claimsSet := _ClaimsSet(*c)

	b, err := json_Marshal(&_claimsSet)
	if err != nil {
		return nil, fmt.Errorf("invalid claims set: %+v: %w", _claimsSet, err)
	}

	if len(c.PrivateClaims) == 0 {
		return b, nil
	}

	privateClaims, err := json.Marshal(c.PrivateClaims)
	if err != nil {
		return nil, fmt.Errorf("invalid private claims: %+v: %w", c.PrivateClaims, err)
	}

	if !bytes_HasSuffix(b, []byte{'}'}) {
		return nil, fmt.Errorf("%s: %w", b, ErrInvalidJSON)
	}

	if !bytes_HasPrefix(privateClaims, []byte{'{'}) {
		return nil, fmt.Errorf("%s: %w", privateClaims, ErrInvalidJSON)
	}

	b[len(b)-1] = ','
	return append(b, privateClaims[1:]...), nil
}

func (c *ClaimsSet) Encode() (encoded string, err error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("json.Marshal: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c *ClaimsSet) Decode(encoded string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.DecodeString: %w", err)
	}

	if err := json.Unmarshal(decoded, c); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}

	return nil
}
