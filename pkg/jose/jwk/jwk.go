package jwk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kunitsuinc/util.go/pkg/cache"
	slicez "github.com/kunitsuinc/util.go/pkg/slices"
)

var (
	ErrCurveNotSupported      = errors.New("jwk: specified curve parameter is not supported")
	ErrKeyIsNotForAlgorithm   = errors.New("jwk: key is not for algorithm")
	ErrResponseIsNotCacheable = errors.New("jwk: response is not cacheable")
)

// ref. JSON Web Key (JWK) https://www.rfc-editor.org/rfc/rfc7517

type JWKSetURL = string //nolint:revive

// JWKSet: A JWK Set is a JSON object that represents a set of JWKs.
//
//   - ref. JWK Set Format https://www.rfc-editor.org/rfc/rfc7517#section-5
//   - ref. https://openid-foundation-japan.github.io/rfc7517.ja.html#JWKSet
type JWKSet struct { //nolint:revive
	// Keys: "keys" parameter is an array of JWK values.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-5.1
	Keys []*JSONWebKey `json:"keys"`
}

// JSONWebKey
//
//   - ref. JSON Web Key (JWK) Format https://www.rfc-editor.org/rfc/rfc7517#section-4
//   - ref. https://openid-foundation-japan.github.io/rfc7517.ja.html#JWKFormat
type JSONWebKey struct {
	// KeyType: "kty" parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC".
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.1
	KeyType string `json:"kty"`

	// PublicKeyUse: "use" parameter identifies the intended use of the public key.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.2
	PublicKeyUse string `json:"use,omitempty"`

	// KeyOperations: "key_ops" parameter identifies the operation(s) for which the key is intended to be used.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.3
	KeyOperations []string `json:"key_ops,omitempty"` //nolint:tagliatelle

	// Algorithm: "alg" parameter identifies the algorithm intended for use with the key.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.4
	Algorithm string `json:"alg,omitempty"`

	// KeyID: "kid" parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.5
	KeyID string `json:"kid,omitempty"`

	// X509URL: "x5u" parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280].
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.6
	X509URL string `json:"x5u,omitempty"`

	// X509CertificateChain: "x5c" parameter contains a chain of one or more PKIX certificates [RFC5280].
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.7
	X509CertificateChain []string `json:"x5c,omitempty"`

	// X509CertificateSHA1Thumbprint: "x5t" parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.8
	X509CertificateSHA1Thumbprint string `json:"x5t,omitempty"`

	// X509CertificateSHA256Thumbprint: "x5t#S256" parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7517#section-4.9
	X509CertificateSHA256Thumbprint string `json:"x5t#S256,omitempty"` //nolint:tagliatelle

	//
	// Parameters for Elliptic Curve Keys
	// ==================================
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2
	//

	// Crv
	//
	// The "crv" (curve) parameter identifies the cryptographic curve used
	// with the key.  Curve values from [DSS] used by this specification
	// are:
	//
	//	o  "P-256"
	//	o  "P-384"
	//	o  "P-521"
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1
	Crv string `json:"crv,omitempty"`

	// X
	//
	// The "x" (x coordinate) parameter contains the x coordinate for the
	// Elliptic Curve point.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2
	X string `json:"x,omitempty"`

	// Y
	//
	// The "y" (y coordinate) parameter contains the y coordinate for the
	// Elliptic Curve point.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3
	Y string `json:"y,omitempty"`

	//
	// Parameters for RSA Keys
	// =======================
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3
	//

	// N: "n" (modulus) parameter contains the modulus value for the RSA public key.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.1
	N string `json:"n,omitempty"`

	// E: "e" (public exponent parameter) contains the exponent value for the RSA public key.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1.2
	E string `json:"e,omitempty"`

	// P: "p" (first prime factor) parameter contains the first prime factor.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.2
	P string `json:"p,omitempty"`

	// Q: "q" (second prime factor) parameter contains the second prime factor.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.3
	Q string `json:"q,omitempty"`

	// DP: "dp" (first factor CRT exponent) parameter contains the Chinese Remainder Theorem (CRT) exponent of the first factor.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.4
	DP string `json:"dp,omitempty"`

	// DQ: "dq" (second factor CRT exponent) parameter contains the CRT exponent of the second factor.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.5
	DQ string `json:"dq,omitempty"`

	// QI: "qi" (first CRT coefficient) parameter contains the CRT coefficient of the second factor.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.6
	QI string `json:"qi,omitempty"`

	// Oth: "oth" (other primes info) parameter contains an array of information about any third and subsequent primes, should they exist.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
	Oth []OtherPrimesInfo `json:"oth,omitempty"`

	//
	// Parameters for Elliptic Curve Keys or RSA Keys
	// ==============================================
	//

	// D is "ECC private key" for EC, or "private exponent" for RSA
	//
	// The "d" (ECC private key) parameter contains the Elliptic Curve private key value.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2.1
	//
	// The "d" (private exponent) parameter contains the private exponent value for the RSA private key.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.1
	D string `json:"d,omitempty"`
}

// OtherPrimesInfo is member struct of "oth" (other primes info).
type OtherPrimesInfo struct {
	// PrimeFactor: "r" (prime factor) parameter within an "oth" array member represents the value of a subsequent prime factor.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.1
	PrimeFactor string `json:"r,omitempty"`

	// FactorCRTExponent: "d" (factor CRT exponent) parameter within an "oth" array member represents the CRT exponent of the corresponding prime factor.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.2
	FactorCRTExponent string `json:"d,omitempty"`

	// FactorCRTCoefficient: "t" (factor CRT coefficient) parameter within an "oth" array member represents the CRT coefficient of the corresponding prime factor.
	//
	//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7.3
	FactorCRTCoefficient string `json:"t,omitempty"`
}

type JSONWebKeyOption func(jwk *JSONWebKey)

func WithKeyType(kty string) JSONWebKeyOption {
	return func(jwk *JSONWebKey) {
		jwk.KeyType = kty
	}
}

func WithKeyID(kid string) JSONWebKeyOption {
	return func(jwk *JSONWebKey) {
		jwk.KeyID = kid
	}
}

func WithAlgorithm(alg string) JSONWebKeyOption {
	return func(jwk *JSONWebKey) {
		jwk.Algorithm = alg
	}
}

// TODO: WithPublicKeyUse() and so on

func (jwk *JSONWebKey) EncodeRSAPublicKey(key *rsa.PublicKey, opts ...JSONWebKeyOption) *JSONWebKey {
	if jwk == nil {
		jwk = new(JSONWebKey)
	}
	for _, opt := range opts {
		opt(jwk)
	}
	jwk.KeyType = "RSA"
	jwk.N = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	jwk.E = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(key.E)))
	return jwk
}

func (jwk *JSONWebKey) DecodeRSAPublicKey() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString: JSONWebKey.N: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString: JSONWebKey.E: %w", err)
	}

	e, err := strconv.Atoi(string(eBytes))
	if err != nil {
		return nil, fmt.Errorf("strconv.Atoi: JSONWebKey.E: %w", err)
	}

	return &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(n),
		E: e,
	}, nil
}

func (jwk *JSONWebKey) EncodeRSAPrivateKey(key *rsa.PrivateKey, opts ...JSONWebKeyOption) *JSONWebKey {
	jwk = jwk.EncodeRSAPublicKey(&key.PublicKey)
	for _, opt := range opts {
		opt(jwk)
	}
	jwk.D = base64.RawURLEncoding.EncodeToString(key.D.Bytes())
	jwk.P = base64.RawURLEncoding.EncodeToString(key.Primes[0].Bytes())
	jwk.Q = base64.RawURLEncoding.EncodeToString(key.Primes[1].Bytes())
	return jwk
}

func (jwk *JSONWebKey) DecodeRSAPrivateKey() (*rsa.PrivateKey, error) {
	pub, err := jwk.DecodeRSAPublicKey()
	if err != nil {
		return nil, err
	}

	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString: JSONWebKey.D: %w", err)
	}

	p, err := base64.RawURLEncoding.DecodeString(jwk.P)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString: JSONWebKey.P: %w", err)
	}

	q, err := base64.RawURLEncoding.DecodeString(jwk.Q)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString: JSONWebKey.Q: %w", err)
	}

	return &rsa.PrivateKey{
		PublicKey: *pub,
		D:         big.NewInt(0).SetBytes(d),
		Primes: []*big.Int{
			big.NewInt(0).SetBytes(p),
			big.NewInt(0).SetBytes(q),
		},
	}, nil
}

func (jwk *JSONWebKey) EncodeECDSAPublicKey(key *ecdsa.PublicKey, opts ...JSONWebKeyOption) *JSONWebKey {
	if jwk == nil {
		jwk = new(JSONWebKey)
	}
	for _, opt := range opts {
		opt(jwk)
	}
	jwk.Crv = key.Params().Name
	jwk.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
	jwk.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
	return jwk
}

func (jwk *JSONWebKey) DecodeECDSAPublicKey() (*ecdsa.PublicKey, error) {
	var crv elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		crv = elliptic.P256()
	case "P-384":
		crv = elliptic.P384()
	case "P-521":
		crv = elliptic.P521()
	default:
		return nil, fmt.Errorf("crv=%s: %w", jwk.Crv, ErrCurveNotSupported)
	}

	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString: JSONWebKey.X: %w", err)
	}

	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString: JSONWebKey.Y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(x),
		Y:     big.NewInt(0).SetBytes(y),
	}, nil
}

func (jwk *JSONWebKey) EncodeECDSAPrivateKey(key *ecdsa.PrivateKey, opts ...JSONWebKeyOption) *JSONWebKey {
	jwk = jwk.EncodeECDSAPublicKey(&key.PublicKey)
	for _, opt := range opts {
		opt(jwk)
	}
	jwk.D = base64.RawURLEncoding.EncodeToString(key.D.Bytes())
	return jwk
}

func (jwk *JSONWebKey) DecodeECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	pub, err := jwk.DecodeECDSAPublicKey()
	if err != nil {
		return nil, err
	}

	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("base64.RawURLEncoding.DecodeString: JSONWebKey.X: %w", err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         big.NewInt(0).SetBytes(d),
	}, nil
}

func (jwk *JSONWebKey) DecodePublicKey(alg string) (crypto.PublicKey, error) {
	switch {
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
		return jwk.DecodeRSAPublicKey()
	case strings.HasPrefix(alg, "ES"):
		return jwk.DecodeECDSAPublicKey()
	}

	return nil, fmt.Errorf("alg=%s: %w", alg, ErrKeyIsNotForAlgorithm)
}

func (jwk *JSONWebKey) DecodePrivateKey(alg string) (crypto.PrivateKey, error) {
	switch {
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
		return jwk.DecodeRSAPrivateKey()
	case strings.HasPrefix(alg, "ES"):
		return jwk.DecodeECDSAPrivateKey()
	}

	return nil, fmt.Errorf("alg=%s: %w", alg, ErrKeyIsNotForAlgorithm)
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

func (d *Client) GetJWKSet(ctx context.Context, jwksURL JWKSetURL) (*JWKSet, error) {
	return d.cacheStore.GetOrSet(jwksURL, func() (*JWKSet, error) { //nolint:wrapcheck
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
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

func GetJWKSet(ctx context.Context, jwksURL JWKSetURL) (*JWKSet, error) {
	return Default.GetJWKSet(ctx, jwksURL)
}

var ErrKidNotFound = errors.New("jwk: kid not found in jwks")

func (jwks *JWKSet) GetJSONWebKey(kid string) (*JSONWebKey, error) {
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == kid {
			return jwk, nil
		}
	}

	return nil, fmt.Errorf("kid=%s: %w", kid, ErrKidNotFound)
}

func HandlerFunc(jwks *JWKSet) (http.HandlerFunc, error) {
	b, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(b)
	}, nil
}
