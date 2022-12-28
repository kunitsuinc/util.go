package jwk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kunitsuinc/util.go/pkg/cache"
	slicez "github.com/kunitsuinc/util.go/pkg/slices"
)

// ref. JSON Web Key (JWK) https://www.rfc-editor.org/rfc/rfc7517

type JWKSetURI = string //nolint:revive

// JWKSet: A JWK Set is a JSON object that represents a set of JWKs.
//
// ref. JWK Set Format https://www.rfc-editor.org/rfc/rfc7517#section-5
// ref. https://openid-foundation-japan.github.io/rfc7517.ja.html#JWKSet
type JWKSet struct { //nolint:revive
	// Keys: "keys" parameter is an array of JWK values.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-5.1
	Keys []*JSONWebKey `json:"keys"`
}

// ref. JSON Web Key (JWK) Format https://www.rfc-editor.org/rfc/rfc7517#section-4
// ref. https://openid-foundation-japan.github.io/rfc7517.ja.html#JWKFormat
type JSONWebKey struct {
	// KeyType: "kty" parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC".
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	KeyType string `json:"kty"`
	// PublicKeyUse: "use" parameter identifies the intended use of the public key.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.2
	PublicKeyUse string `json:"use,omitempty"`
	// KeyOperations: "key_ops" parameter identifies the operation(s) for which the key is intended to be used.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.3
	KeyOperations []string `json:"key_ops,omitempty"` //nolint:tagliatelle
	// Algorithm: "alg" parameter identifies the algorithm intended for use with the key.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.4
	Algorithm string `json:"alg,omitempty"`
	// KeyID: "kid" parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.5
	KeyID string `json:"kid,omitempty"`
	// X509URL: "x5u" parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280].
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.6
	X509URL string `json:"x5u,omitempty"`
	// X509CertificateChain: "x5c" parameter contains a chain of one or more PKIX certificates [RFC5280].
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.7
	X509CertificateChain []string `json:"x5c,omitempty"`
	// X509CertificateSHA1Thumbprint: "x5t" parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.8
	X509CertificateSHA1Thumbprint string `json:"x5t,omitempty"`
	// X509CertificateSHA256Thumbprint: "x5t#S256" parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].
	//	- ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.9
	X509CertificateSHA256Thumbprint string `json:"x5t#S256,omitempty"` //nolint:tagliatelle

	//
	// Parameters for Elliptic Curve Keys
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2
	//

	// Crv: "crv" parameter identifies the cryptographic curve used with the key.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1
	Crv string `json:"crv,omitempty"`
	// X: "x" (X Coordinate) parameter contains the x coordinate for the Elliptic Curve point.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2
	X string `json:"x,omitempty"`
	// Y: "y" (Y Coordinate) parameter contains the y coordinate for the Elliptic Curve point.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
	Y string `json:"y,omitempty"`

	//
	// Parameters for RSA Keys
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3
	//

	// N: "n" (modulus) parameter contains the modulus value for the RSA public key.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
	N string `json:"n,omitempty"`
	// E: "e" (public exponent parameter) contains the exponent value for the RSA public key.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.2
	E string `json:"e,omitempty"`
	// P: "p" (first prime factor) parameter contains the first prime factor.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
	P string `json:"p,omitempty"`
	// Q: "q" (second prime factor) parameter contains the second prime factor.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.3
	Q string `json:"q,omitempty"`
	// DP: "dp" (first factor CRT exponent) parameter contains the Chinese Remainder Theorem (CRT) exponent of the first factor.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.4
	DP string `json:"dp,omitempty"`
	// DQ: "dq" (second factor CRT exponent) parameter contains the CRT exponent of the second factor.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.5
	DQ string `json:"dq,omitempty"`
	// QI: "qi" (first CRT coefficient) parameter contains the CRT coefficient of the second factor.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.6
	QI string `json:"qi,omitempty"`
	// Oth: "oth" (other primes info) parameter contains an array of information about any third and subsequent primes, should they exist.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
	Oth []OtherPrimesInfo `json:"oth,omitempty"`

	// D is "ECC private key" for EC, or "private exponent" for RSA
	//
	// The "d" (ECC private key) parameter contains the Elliptic Curve private key value.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2.1
	//
	// The "d" (private exponent) parameter contains the private exponent value for the RSA private key.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.1
	D string `json:"d,omitempty"`
}

// OtherPrimesInfo is member struct of "oth" (other primes info).
type OtherPrimesInfo struct {
	// PrimeFactor: "r" (prime factor) parameter within an "oth" array member represents the value of a subsequent prime factor.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.1
	PrimeFactor string `json:"r,omitempty"`
	// FactorCRTExponent: "d" (factor CRT exponent) parameter within an "oth" array member represents the CRT exponent of the corresponding prime factor.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.2
	FactorCRTExponent string `json:"d,omitempty"`
	// FactorCRTCoefficient: "t" (factor CRT coefficient) parameter within an "oth" array member represents the CRT coefficient of the corresponding prime factor.
	//	- ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.3
	FactorCRTCoefficient string `json:"t,omitempty"`
}

type Client struct { //nolint:revive
	client     *http.Client
	cacheStore *cache.Store[*JWKSet]
}

func NewClient(ctx context.Context, opts ...ClientOption) *Client {
	d := &Client{
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				// do not redirect for avoiding open redirect from jku.
				return http.ErrUseLastResponse
			},
		},
		cacheStore: cache.NewStore(ctx, cache.WithDefaultTTL[*JWKSet](10*time.Minute)),
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

type ClientOption func(*Client)

func WithHTTPClient(client *http.Client) ClientOption {
	return func(d *Client) {
		d.client = client
	}
}

func WithCacheStore(store *cache.Store[*JWKSet]) ClientOption {
	return func(d *Client) {
		d.cacheStore = store
	}
}

var ErrResponseIsNotCacheable = errors.New("jwk: response is not cacheable")

func (d *Client) GetJWKSet(ctx context.Context, jwksURI JWKSetURI) (*JWKSet, error) {
	return d.cacheStore.GetOrSet(jwksURI, func() (*JWKSet, error) { //nolint:wrapcheck
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
		if err != nil {
			return nil, fmt.Errorf("http.NewRequestWithContext: %w", err)
		}

		resp, err := d.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("(*http.Client).Do: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || 300 <= resp.StatusCode {
			body, _ := io.ReadAll(resp.Body)
			bodyCutOff := slicez.CutOff(body, 100)
			return nil, fmt.Errorf("code=%d body=%q: %w", resp.StatusCode, string(bodyCutOff), ErrResponseIsNotCacheable)
		}

		r := new(JWKSet)
		if err := json.NewDecoder(resp.Body).Decode(r); err != nil {
			return nil, fmt.Errorf("(*json.Decoder).Decode(*discovery.JWKSet): %w", err)
		}

		return r, nil
	})
}

//nolint:gochecknoglobals
var (
	Default = NewClient(context.Background())
)

func GetJWKSet(ctx context.Context, jwksURI JWKSetURI) (*JWKSet, error) {
	return Default.GetJWKSet(ctx, jwksURI)
}

var ErrKidNotFound = errors.New("jwk: kid not found in jwks")

func (jwks *JWKSet) GetJSONWebKey(kid string) (*JSONWebKey, error) {
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == kid {
			return jwk, nil
		}
	}

	return nil, ErrKidNotFound
}
