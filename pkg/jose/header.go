package jose

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/kunitsuinc/util.go/pkg/jose/jwk"
)

// Header
//
//   - ref. JOSE Header - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4
//   - ref. JOSE Header - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4
type Header struct {
	// Algorithm
	//
	//   - ref. "alg" (Algorithm) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
	//   - ref. "alg" (Algorithm) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.1
	Algorithm string `json:"alg,omitempty"`

	// EncryptionAlgorithm
	//
	//   - ref. "enc" (Encryption Algorithm) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.2
	EncryptionAlgorithm string `json:"enc,omitempty"`

	// CompressionAlgorithm
	//
	//   - ref. "zip" (Compression Algorithm) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.3
	CompressionAlgorithm string `json:"zip,omitempty"`

	// JwksURL
	//
	//   - ref. "jku" (JWK Set URL) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.2
	//   - ref. "jku" (JWK Set URL) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.4
	JwksURL string `json:"jku,omitempty"`

	// JSONWebKey
	//
	//   - ref. "jwk" (JSON Web Key) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.3
	//   - ref. "jwk" (JSON Web Key) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.5
	JSONWebKey *jwk.JSONWebKey `json:"jwk,omitempty"`

	// KeyID
	//
	//   - ref. "kid" (Key ID) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4
	//   - ref. "kid" (Key ID) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.6
	KeyID string `json:"kid,omitempty"`

	// X509URL
	//
	//   - ref. "x5u" (X.509 URL) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.5
	//   - ref. "x5u" (X.509 URL) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.7
	X509URL string `json:"x5u,omitempty"`

	// X509CertificateChain
	//
	//   - ref. "x5c" (X.509 Certificate Chain) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
	//   - ref. "x5c" (X.509 Certificate Chain) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.8
	X509CertificateChain []string `json:"x5c,omitempty"`

	// X509CertificateSHA1Thumbprint
	//
	//   - ref. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.7
	//   - ref. "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.9
	X509CertificateSHA1Thumbprint string `json:"x5t,omitempty"`

	// X509CertificateSHA256Thumbprint
	//
	//   - ref. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.8
	//   - ref. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.10
	X509CertificateSHA256Thumbprint string `json:"x5t#S256,omitempty"` //nolint:tagliatelle

	// Type
	//
	//   - ref. "typ" (Type) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9
	//   - ref. "typ" (Type) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.11
	Type string `json:"typ,omitempty"`

	// ContentType
	//
	//   - ref. "cty" (Content Type) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.10
	//   - ref. "cty" (Content Type) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.12
	ContentType string `json:"cty,omitempty"`

	// Critical
	//
	//   - ref. "crit" (Critical) Header Parameter - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
	//   - ref. "crit" (Critical) Header Parameter - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.1.13
	Critical []string `json:"crit,omitempty"`

	// PrivateHeaderParameters
	//
	//   - ref. Private Header Parameter Names - JSON Web Signature (JWS)  https://www.rfc-editor.org/rfc/rfc7515#section-4.3
	//   - ref. Private Header Parameter Names - JSON Web Encryption (JWE) https://www.rfc-editor.org/rfc/rfc7516#section-4.3
	PrivateHeaderParameters PrivateHeaderParameters `json:"-"`
}

type PrivateHeaderParameters map[string]any

type HeaderParameter func(h *Header)

func WithAlgorithm(alg string) HeaderParameter {
	return func(h *Header) {
		h.Algorithm = alg
	}
}

func WithEncryptionAlgorithm(enc string) HeaderParameter {
	return func(h *Header) {
		h.EncryptionAlgorithm = enc
	}
}

func WithCompressionAlgorithm(zip string) HeaderParameter {
	return func(h *Header) {
		h.CompressionAlgorithm = zip
	}
}

func WithJwksURL(jku string) HeaderParameter {
	return func(h *Header) {
		h.JwksURL = jku
	}
}

func WithJSONWebKey(jwk *jwk.JSONWebKey) HeaderParameter {
	return func(h *Header) {
		h.JSONWebKey = jwk
	}
}

func WithKeyID(kid string) HeaderParameter {
	return func(h *Header) {
		h.KeyID = kid
	}
}

func WithX509URL(x5u string) HeaderParameter {
	return func(h *Header) {
		h.X509URL = x5u
	}
}

func WithX509CertificateChain(x5c []string) HeaderParameter {
	return func(h *Header) {
		h.X509CertificateChain = x5c
	}
}

func WithX509CertificateSHA1Thumbprint(x5t string) HeaderParameter {
	return func(h *Header) {
		h.X509CertificateSHA1Thumbprint = x5t
	}
}

func WithX509CertificateSHA256Thumbprint(x5tS256 string) HeaderParameter {
	return func(h *Header) {
		h.X509CertificateSHA256Thumbprint = x5tS256
	}
}

func WithType(typ string) HeaderParameter {
	return func(h *Header) {
		h.Type = typ
	}
}

func WithContentType(cty string) HeaderParameter {
	return func(h *Header) {
		h.ContentType = cty
	}
}

func WithCritical(crit []string) HeaderParameter {
	return func(h *Header) {
		h.Critical = crit
	}
}

func WithPrivateHeaderParameter(name string, value any) HeaderParameter {
	return func(h *Header) {
		h.PrivateHeaderParameters[name] = value
	}
}

// NewHeader
//
// Example:
//
//	header := jose.NewHeader(
//		jose.WithAlgorithm(jwa.HS256),
//		jose.WithType("JWT"),
//	)
func NewHeader(parameters ...HeaderParameter) *Header {
	h := &Header{
		PrivateHeaderParameters: make(PrivateHeaderParameters),
	}

	for _, parameter := range parameters {
		parameter(h)
	}

	return h
}

var ErrInvalidJSON = errors.New("jose: invalid JSON")

func (h *Header) UnmarshalJSON(data []byte) (err error) {
	// avoid recursion
	type _Header Header
	_header := _Header{}

	err = json.Unmarshal(data, &_header)
	if err == nil {
		*h = Header(_header)
	}

	privateHeaderParameters := make(map[string]any)

	err = json.Unmarshal(data, &privateHeaderParameters)
	if err == nil {
		typ := reflect.TypeOf(_header)
		for i := 0; i < typ.NumField(); i++ {
			delete(privateHeaderParameters, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}

		h.PrivateHeaderParameters = privateHeaderParameters
	}

	return err //nolint:wrapcheck
}

func (h *Header) MarshalJSON() (data []byte, err error) {
	return h.marshalJSON(json.Marshal, bytes.HasSuffix, bytes.HasPrefix)
}

func (h *Header) marshalJSON(
	json_Marshal func(v any) ([]byte, error), //nolint:revive,stylecheck
	bytes_HasSuffix func(s []byte, suffix []byte) bool, //nolint:revive,stylecheck
	bytes_HasPrefix func(s []byte, prefix []byte) bool, //nolint:revive,stylecheck
) (data []byte, err error) {
	// avoid recursion
	type _Header Header
	_header := _Header(*h)

	b, err := json_Marshal(&_header)
	if err != nil {
		return nil, fmt.Errorf("invalid jose header: %+v: %w", _header, err)
	}

	if len(h.PrivateHeaderParameters) == 0 {
		return b, nil
	}

	privateHeaderParameters, err := json.Marshal(h.PrivateHeaderParameters)
	if err != nil {
		return nil, fmt.Errorf("invalid private header parameters: %+v: %w", h.PrivateHeaderParameters, err)
	}

	if !bytes_HasSuffix(b, []byte{'}'}) {
		return nil, fmt.Errorf("%s: %w", b, ErrInvalidJSON)
	}

	if !bytes_HasPrefix(privateHeaderParameters, []byte{'{'}) {
		return nil, fmt.Errorf("%s: %w", privateHeaderParameters, ErrInvalidJSON)
	}

	b[len(b)-1] = ','
	return append(b, privateHeaderParameters[1:]...), nil
}

func (h *Header) Encode() (string, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("json.Marshal: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *Header) Decode(header string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.DecodeString: %w", err)
	}

	if err := json.Unmarshal(decoded, h); err != nil {
		return fmt.Errorf("json.Unmarshal: %w", err)
	}

	return nil
}
