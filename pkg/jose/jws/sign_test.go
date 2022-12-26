package jws_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	x509z "github.com/kunitsuinc/util.go/pkg/crypto/x509"
	"github.com/kunitsuinc/util.go/pkg/jose/jws"
	"github.com/kunitsuinc/util.go/pkg/must"
	testz "github.com/kunitsuinc/util.go/pkg/test"
)

type testCaseSign struct {
	Alg           string
	SigningInput  string
	Key           crypto.PrivateKey
	Signature     string
	ResultHandler func(t *testing.T, testCase testCaseSign, actual string, err error)
}

var testCasesSign = map[string]testCaseSign{
	"success(HS256)": {
		Alg:          "HS256",
		SigningInput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		Key:          []byte(`your-256-bit-secret`),
		Signature:    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(HS256,jws.ErrInvalidKeyReceived)": {
		Alg:          "HS256",
		SigningInput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		Key:          0,
		Signature:    "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(HS384)": {
		Alg:          "HS384",
		SigningInput: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		Key:          []byte(`your-384-bit-secret`),
		Signature:    "8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(HS384,jws.ErrInvalidKeyReceived)": {
		Alg:          "HS384",
		SigningInput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		Key:          0,
		Signature:    "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(HS512)": {
		Alg:          "HS512",
		SigningInput: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		Key:          []byte(`your-512-bit-secret`),
		Signature:    "_MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(HS512,jws.ErrInvalidKeyReceived)": {
		Alg:          "HS512",
		SigningInput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		Key:          0,
		Signature:    "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(RS256)": {
		Alg:          "RS256",
		SigningInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		Signature:    "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(RS256,rsa.SignPKCS1v15)": {
		Alg:          "RS256",
		SigningInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key: &rsa.PrivateKey{
			PublicKey: *must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
			D:         big.NewInt(0),
			Primes:    []*big.Int{big.NewInt(0), big.NewInt(0)},
		},
		Signature: "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if expect := "rsa: internal error"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), expect, err)
			}
		},
	},
	"failure(RS256,jws.ErrInvalidKeyReceived)": {
		Alg:          "RS256",
		SigningInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		Signature:    "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(RS384)": {
		Alg:          "RS384",
		SigningInput: "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		Signature:    "o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(RS384,jws.ErrInvalidKeyReceived)": {
		Alg:          "RS384",
		SigningInput: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		Signature:    "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(RS512)": {
		Alg:          "RS512",
		SigningInput: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		Signature:    "jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(RS512,jws.ErrInvalidKeyReceived)": {
		Alg:          "RS512",
		SigningInput: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		Signature:    "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if testCase.Signature != actual {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), testCase.Signature, actual)
			}
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(ES256)": {
		Alg:          "ES256",
		SigningInput: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseECDSAPrivateKeyPEM([]byte(testz.TestECDSAPrivateKey256BitPEM))),
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
			token := testCase.SigningInput + "." + actual
			if _, _, err := jws.VerifySignature(token, must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM)))); err != nil {
				t.Errorf("%s: expect(%v) != actual(%v): token: %s", t.Name(), nil, err, token)
			}
		},
	},
	"failure(ES256,jws.ErrInvalidKeyReceived)": {
		Alg:          "ES256",
		SigningInput: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		ResultHandler: func(t *testing.T, _ testCaseSign, actual string, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), jws.ErrInvalidKeyReceived, err)
			}
		},
	},
	"failure(ES256,ecdsa.Sign)": {
		Alg:          "ES256",
		SigningInput: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: &elliptic.CurveParams{P: big.NewInt(0), N: big.NewInt(0), B: big.NewInt(0), Gx: big.NewInt(0), Gy: big.NewInt(0), BitSize: 0, Name: ""}, X: big.NewInt(0), Y: big.NewInt(0)}, D: big.NewInt(0)},
		ResultHandler: func(t *testing.T, _ testCaseSign, actual string, err error) {
			t.Helper()
			if expect := "ecdsa.Sign: zero parameter"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), expect, err)
			}
		},
	},
	"success(ES384)": {
		Alg:          "ES384",
		SigningInput: "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseECDSAPrivateKeyPEM([]byte(testz.TestECDSAPrivateKey384BitPEM))),
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
			token := testCase.SigningInput + "." + actual
			if _, _, err := jws.VerifySignature(token, must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey384BitPEM)))); err != nil {
				t.Errorf("%s: expect(%v) != actual(%v): token: %s", t.Name(), nil, err, token)
			}
		},
	},
	"failure(ES384,jws.ErrInvalidKeyReceived)": {
		Alg:          "ES384",
		SigningInput: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		ResultHandler: func(t *testing.T, _ testCaseSign, actual string, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), jws.ErrInvalidKeyReceived, err)
			}
		},
	},
	"success(ES512)": {
		Alg:          "ES512",
		SigningInput: "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseECDSAPrivateKeyPEM([]byte(testz.TestECDSAPrivateKey521bitPEM))),
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
			token := testCase.SigningInput + "." + actual
			if _, _, err := jws.VerifySignature(token, must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey521BitPEM)))); err != nil {
				t.Errorf("%s: expect(%v) != actual(%v): token: %s", t.Name(), nil, err, token)
			}
		},
	},
	"failure(ES512,jws.ErrInvalidKeyReceived)": {
		Alg:          "ES512",
		SigningInput: "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		ResultHandler: func(t *testing.T, _ testCaseSign, actual string, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), jws.ErrInvalidKeyReceived, err)
			}
		},
	},
	"success(PS256)": {
		Alg:          "PS256",
		SigningInput: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		Signature:    "iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
			token := testCase.SigningInput + "." + actual
			if _, _, err := jws.VerifySignature(token, must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM)))); err != nil {
				t.Errorf("%s: expect(%v) != actual(%v): token: %s", t.Name(), nil, err, token)
			}
		},
	},
	"failure(PS256,jws.ErrInvalidKeyReceived)": {
		Alg:          "PS256",
		SigningInput: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(PS256,rsa.SignPSS)": {
		Alg:          "PS256",
		SigningInput: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key: &rsa.PrivateKey{
			PublicKey: *must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
			D:         big.NewInt(0),
			Primes:    []*big.Int{big.NewInt(0), big.NewInt(0)},
		},
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if expect := "rsa.SignPSS: rsa: internal error"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("%s: expect(%v) != actual(%v)", t.Name(), expect, err)
			}
		},
	},
	"success(PS384)": {
		Alg:          "PS384",
		SigningInput: "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
			token := testCase.SigningInput + "." + actual
			if _, _, err := jws.VerifySignature(token, must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM)))); err != nil {
				t.Errorf("%s: expect(%v) != actual(%v): token: %s", t.Name(), nil, err, token)
			}
		},
	},
	"failure(PS384,jws.ErrInvalidKeyReceived)": {
		Alg:          "PS384",
		SigningInput: "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(PS512)": {
		Alg:          "PS512",
		SigningInput: "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if err != nil {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
			token := testCase.SigningInput + "." + actual
			if _, _, err := jws.VerifySignature(token, must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM)))); err != nil {
				t.Errorf("%s: expect(%v) != actual(%v): token: %s", t.Name(), nil, err, token)
			}
		},
	},
	"failure(PS512,jws.ErrInvalidKeyReceived)": {
		Alg:          "PS512",
		SigningInput: "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          0,
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(jws.ErrAlgorithmNoneIsNotSupported)": {
		Alg:          "none",
		SigningInput: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		Signature:    "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrAlgorithmNoneIsNotSupported) {
				t.Errorf("%s: err != jws.ErrAlgorithmNoneIsNotSupported: %v", t.Name(), err)
			}
		},
	},
	"failure(jws.ErrInvalidAlgorithm)": {
		Alg:          "invalid",
		SigningInput: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		Key:          must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM))),
		Signature:    "",
		ResultHandler: func(t *testing.T, testCase testCaseSign, actual string, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidAlgorithm) {
				t.Errorf("%s: err != jws.ErrInvalidAlgorithm: %v", t.Name(), err)
			}
		},
	},
}

func TestSign(t *testing.T) {
	t.Parallel()

	for testName, testCase := range testCasesSign {
		t, k, v := t, testName, testCase
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			actual, err := jws.Sign(v.Alg, v.SigningInput, v.Key)
			v.ResultHandler(t, v, actual, err)
		})
	}
}
