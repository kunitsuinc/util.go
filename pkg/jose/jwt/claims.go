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
	// The "sub" (subject) claim identifies the principal that is the
	// subject of the JWT.  The claims in a JWT are normally statements
	// about the subject.  The subject value MUST either be scoped to be
	// locally unique in the context of the issuer or be globally unique.
	// The processing of this claim is generally application specific.  The
	// "sub" value is a case-sensitive string containing a StringOrURI
	// value.  Use of this claim is OPTIONAL.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// Audience
	//
	// The "aud" (audience) claim identifies the recipients that the JWT is
	// intended for.  Each principal intended to process the JWT MUST
	// identify itself with a value in the audience claim.  If the principal
	// processing the claim does not identify itself with a value in the
	// "aud" claim when this claim is present, then the JWT MUST be
	// rejected.  In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value.  The
	// interpretation of audience values is generally application specific.
	// Use of this claim is OPTIONAL.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
	Audience string `json:"aud,omitempty"`

	// ExpirationTime
	//
	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT MUST NOT be accepted for processing.  The
	// processing of the "exp" claim requires that the current date/time
	// MUST be before the expiration date/time listed in the "exp" claim.
	// Implementers MAY provide for some small leeway, usually no more than
	// a few minutes, to account for clock skew.  Its value MUST be a number
	// containing a NumericDate value.  Use of this claim is OPTIONAL.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
	ExpirationTime int64 `json:"exp,omitempty"`

	// NotBefore
	//
	// The "nbf" (not before) claim identifies the time before which the JWT
	// MUST NOT be accepted for processing.  The processing of the "nbf"
	// claim requires that the current date/time MUST be after or equal to
	// the not-before date/time listed in the "nbf" claim.  Implementers MAY
	// provide for some small leeway, usually no more than a few minutes, to
	// account for clock skew.  Its value MUST be a number containing a
	// NumericDate value.  Use of this claim is OPTIONAL.
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
