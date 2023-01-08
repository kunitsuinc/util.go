package jwa_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	x509z "github.com/kunitsuinc/util.go/pkg/crypto/x509"
	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
	"github.com/kunitsuinc/util.go/pkg/must"
	testz "github.com/kunitsuinc/util.go/pkg/test"
)

var signTestCases = map[string]struct {
	alg          string
	key          any
	signingInput string
	sigHandler   func(t *testing.T, signatureEncoded string)
	errHandler   func(t *testing.T, err error)
}{
	//
	// HS256
	//
	fmt.Sprintf("success(%s)", jwa.HS256): {
		alg:          string(jwa.HS256),
		key:          []byte(`your-256-bit-secret`),
		signingInput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.HS256): {
		alg:          string(jwa.HS256),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// HS384
	//
	fmt.Sprintf("success(%s)", jwa.HS384): {
		alg:          string(jwa.HS384),
		key:          []byte(`your-384-bit-secret`),
		signingInput: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, "8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ"; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.HS384): {
		alg:          string(jwa.HS384),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// HS512
	//
	fmt.Sprintf("success(%s)", jwa.HS512): {
		alg:          string(jwa.HS512),
		key:          []byte(`your-512-bit-secret`),
		signingInput: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, "_MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg"; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.HS512): {
		alg:          string(jwa.HS512),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// RS256
	//
	fmt.Sprintf("success(%s)", jwa.RS256): {
		alg:          string(jwa.RS256),
		key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		signingInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.RS256): {
		alg:          string(jwa.RS256),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,rsa.SignPKCS1v15)", jwa.RS256): {
		alg:          string(jwa.RS256),
		key:          &rsa.PrivateKey{PublicKey: *must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))), D: big.NewInt(0), Primes: []*big.Int{big.NewInt(0), big.NewInt(0)}},
		signingInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "rsa: internal error"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	//
	// RS384
	//
	fmt.Sprintf("success(%s)", jwa.RS384): {
		alg:          string(jwa.RS384),
		key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		signingInput: "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, "o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ"; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.RS384): {
		alg:          string(jwa.RS384),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// RS512
	//
	fmt.Sprintf("success(%s)", jwa.RS512): {
		alg:          string(jwa.RS512),
		key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		signingInput: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, "jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ"; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.RS512): {
		alg:          string(jwa.RS512),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// ES256
	//
	fmt.Sprintf("success(%s)", jwa.ES256): {
		alg:          string(jwa.ES256),
		key:          must.One(x509z.ParseECDSAPrivateKeyPEM([]byte(testz.TestECDSAPrivateKey256BitPEM))),
		signingInput: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if err := jwa.JWSAlgorithmES256.Verify(must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))), "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0", signatureEncoded); err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.ES256): {
		alg:          string(jwa.ES256),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,ecdsa.Sign)", jwa.ES256): {
		alg:          string(jwa.ES256),
		key:          &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: &elliptic.CurveParams{P: big.NewInt(0), N: big.NewInt(0), B: big.NewInt(0), Gx: big.NewInt(0), Gy: big.NewInt(0), BitSize: 0, Name: ""}, X: big.NewInt(0), Y: big.NewInt(0)}, D: big.NewInt(0)},
		signingInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "zero parameter"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	//
	// ES384
	//
	fmt.Sprintf("success(%s)", jwa.ES384): {
		alg:          string(jwa.ES384),
		key:          must.One(x509z.ParseECDSAPrivateKeyPEM([]byte(testz.TestECDSAPrivateKey256BitPEM))),
		signingInput: "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if err := jwa.JWSAlgorithmES384.Verify(must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))), "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0", signatureEncoded); err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.ES384): {
		alg:          string(jwa.ES384),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// ES512
	//
	fmt.Sprintf("success(%s)", jwa.ES512): {
		alg:          string(jwa.ES512),
		key:          must.One(x509z.ParseECDSAPrivateKeyPEM([]byte(testz.TestECDSAPrivateKey256BitPEM))),
		signingInput: "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if err := jwa.JWSAlgorithmES512.Verify(must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))), "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0", signatureEncoded); err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.ES512): {
		alg:          string(jwa.ES512),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// PS256
	//
	fmt.Sprintf("success(%s)", jwa.PS256): {
		alg:          string(jwa.PS256),
		key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		signingInput: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if err := jwa.JWSAlgorithmPS256.Verify(must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))), "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0", signatureEncoded); err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.PS256): {
		alg:          string(jwa.PS256),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,rsa.SignPKCS1v15)", jwa.PS256): {
		alg:          string(jwa.PS256),
		key:          &rsa.PrivateKey{PublicKey: *must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))), D: big.NewInt(0), Primes: []*big.Int{big.NewInt(0), big.NewInt(0)}},
		signingInput: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "rsa: internal error"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	//
	// PS384
	//
	fmt.Sprintf("success(%s)", jwa.PS384): {
		alg:          string(jwa.PS384),
		key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		signingInput: "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if err := jwa.JWSAlgorithmPS384.Verify(must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))), "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0", signatureEncoded); err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.PS384): {
		alg:          string(jwa.PS384),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// PS512
	//
	fmt.Sprintf("success(%s)", jwa.PS512): {
		alg:          string(jwa.PS512),
		key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		signingInput: "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if err := jwa.JWSAlgorithmPS512.Verify(must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))), "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0", signatureEncoded); err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.PS512): {
		alg:          string(jwa.PS512),
		key:          "invalidKey",
		signingInput: "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// none
	//
	fmt.Sprintf("failure(%s,jwa.ErrAlgorithmNoneIsNotSupported)", jwa.None): {
		alg: string(jwa.None),
		sigHandler: func(t *testing.T, signatureEncoded string) { //nolint:thelper
			if actual, expect := signatureEncoded, ""; actual != expect {
				t.Errorf("❌: actual != expect: %v", actual)
			}
		},
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrAlgorithmNoneIsNotSupported) {
				t.Errorf("❌: err != jwa.ErrAlgorithmNoneIsNotSupported: %v", err)
			}
		},
	},
}

func TestJWSAlgorithm_Sign(t *testing.T) {
	t.Parallel()
	for name, testCase := range signTestCases {
		t, name, testCase := t, name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			actual, err := jwa.JWS(testCase.alg).Sign(testCase.key, testCase.signingInput)
			testCase.sigHandler(t, actual)
			testCase.errHandler(t, err)
		})
	}
}
