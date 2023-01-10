package jwa_test

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"

	x509z "github.com/kunitsuinc/util.go/pkg/crypto/x509"
	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
	"github.com/kunitsuinc/util.go/pkg/must"
	testz "github.com/kunitsuinc/util.go/pkg/test"
)

var verifyTestCases = map[string]struct {
	alg              string
	key              any
	signingInput     string
	signatureEncoded string
	errHandler       func(t *testing.T, err error)
}{
	//
	// HS256
	//
	fmt.Sprintf("success(%s)", jwa.HS256): {
		alg:              jwa.HS256,
		key:              []byte(`your-256-bit-secret`),
		signingInput:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		signatureEncoded: "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.HS256): {
		alg:              jwa.HS256,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		signatureEncoded: "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,base64.RawURLEncoding.DecodeString)", jwa.HS256): {
		alg:              jwa.HS256,
		key:              []byte(`your-256-bit-secret`),
		signingInput:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		signatureEncoded: "inv@lidBase64",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "illegal base64 data at input byte 3"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrFailedToVerifySignature)", jwa.HS256): {
		alg:              jwa.HS256,
		key:              []byte(`your-256-bit-secret`),
		signingInput:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		signatureEncoded: "failure",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrFailedToVerifySignature) {
				t.Errorf("❌: err != jwa.ErrFailedToVerifySignature: %v", err)
			}
		},
	},
	//
	// HS384
	//
	fmt.Sprintf("success(%s)", jwa.HS384): {
		alg:              jwa.HS384,
		key:              []byte(`your-384-bit-secret`),
		signingInput:     "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		signatureEncoded: "8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.HS384): {
		alg:              jwa.HS384,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		signatureEncoded: "8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ",
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
		alg:              jwa.HS512,
		key:              []byte(`your-512-bit-secret`),
		signingInput:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		signatureEncoded: "_MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.HS512): {
		alg:              jwa.HS512,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		signatureEncoded: "_MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg",
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
		alg:              jwa.RS256,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.RS256): {
		alg:              jwa.RS256,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,base64.RawURLEncoding.DecodeString)", jwa.RS256): {
		alg:              jwa.RS256,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "inv@lidBase64",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "illegal base64 data at input byte 3"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	fmt.Sprintf("failure(%s,rsa.VerifyPKCS1v15)", jwa.RS256): {
		alg:              jwa.RS256,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "failure",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, rsa.ErrVerification) {
				t.Errorf("%s: err != rsa.ErrVerification: %v", t.Name(), err)
			}
		},
	},
	//
	// RS384
	//
	fmt.Sprintf("success(%s)", jwa.RS384): {
		alg:              jwa.RS384,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.RS384): {
		alg:              jwa.RS384,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ",
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
		alg:              jwa.RS512,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.RS512): {
		alg:              jwa.RS512,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ",
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
		alg:              jwa.ES256,
		key:              must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))),
		signingInput:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.ES256): {
		alg:              jwa.ES256,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,base64.RawURLEncoding.DecodeString)", jwa.ES256): {
		alg:              jwa.ES256,
		key:              must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))),
		signingInput:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "inv@lidBase64",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "illegal base64 data at input byte 3"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	fmt.Sprintf("failure(%s,keySize)", jwa.ES256): {
		alg:              jwa.ES256,
		key:              must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))),
		signingInput:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "failure",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "len(signature)=5 != keySize*2=64: jwa: failed to verify signature"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrFailedToVerifySignature)", jwa.ES256): {
		alg:              jwa.ES256,
		key:              must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))),
		signingInput:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "failure_failure_failure_failure_failure_failure_failure_failure_failure_failure_failur",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "ecdsa.Verify: jwa: failed to verify signature"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	//
	// ES384
	//
	fmt.Sprintf("success(%s)", jwa.ES384): {
		alg:              jwa.ES384,
		key:              must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey384BitPEM))),
		signingInput:     "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.ES384): {
		alg:              jwa.ES384,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj",
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
		alg:              jwa.ES512,
		key:              must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey521BitPEM))),
		signingInput:     "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.ES512): {
		alg:              jwa.ES512,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk",
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
		alg:              jwa.PS256,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.PS256): {
		alg:              jwa.PS256,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,base64.RawURLEncoding.DecodeString)", jwa.PS256): {
		alg:              jwa.PS256,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "inv@lidBase64",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if expect := "illegal base64 data at input byte 3"; err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("❌: err != expect(%s): %v", expect, err)
			}
		},
	},
	fmt.Sprintf("failure(%s,rsa.VerifyPSS)", jwa.PS256): {
		alg:              jwa.PS256,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "failure",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, rsa.ErrVerification) {
				t.Errorf("%s: err != rsa.ErrVerification: %v", t.Name(), err)
			}
		},
	},
	//
	// PS384
	//
	fmt.Sprintf("success(%s)", jwa.PS384): {
		alg:              jwa.PS384,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "Lfe_aCQme_gQpUk9-6l9qesu0QYZtfdzfy08w8uqqPH_gnw-IVyQwyGLBHPFBJHMbifdSMxPjJjkCD0laIclhnBhowILu6k66_5Y2z78GHg8YjKocAvB-wSUiBhuV6hXVxE5emSjhfVz2OwiCk2bfk2hziRpkdMvfcITkCx9dmxHU6qcEIsTTHuH020UcGayB1-IoimnjTdCsV1y4CMr_ECDjBrqMdnontkqKRIM1dtmgYFsJM6xm7ewi_ksG_qZHhaoBkxQ9wq9OVQRGiSZYowCp73d2BF3jYMhdmv2JiaUz5jRvv6lVU7Quq6ylVAlSPxeov9voYHO1mgZFCY1kQ",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.PS384): {
		alg:              jwa.PS384,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "Lfe_aCQme_gQpUk9-6l9qesu0QYZtfdzfy08w8uqqPH_gnw-IVyQwyGLBHPFBJHMbifdSMxPjJjkCD0laIclhnBhowILu6k66_5Y2z78GHg8YjKocAvB-wSUiBhuV6hXVxE5emSjhfVz2OwiCk2bfk2hziRpkdMvfcITkCx9dmxHU6qcEIsTTHuH020UcGayB1-IoimnjTdCsV1y4CMr_ECDjBrqMdnontkqKRIM1dtmgYFsJM6xm7ewi_ksG_qZHhaoBkxQ9wq9OVQRGiSZYowCp73d2BF3jYMhdmv2JiaUz5jRvv6lVU7Quq6ylVAlSPxeov9voYHO1mgZFCY1kQ",
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
		alg:              jwa.PS512,
		key:              must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		signingInput:     "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "J5W09-rNx0pt5_HBiydR-vOluS6oD-RpYNa8PVWwMcBDQSXiw6-EPW8iSsalXPspGj3ouQjAnOP_4-zrlUUlvUIt2T79XyNeiKuooyIFvka3Y5NnGiOUBHWvWcWp4RcQFMBrZkHtJM23sB5D7Wxjx0-HFeNk-Y3UJgeJVhg5NaWXypLkC4y0ADrUBfGAxhvGdRdULZivfvzuVtv6AzW6NRuEE6DM9xpoWX_4here-yvLS2YPiBTZ8xbB3axdM99LhES-n52lVkiX5AWg2JJkEROZzLMpaacA_xlbUz_zbIaOaoqk8gB5oO7kI6sZej3QAdGigQy-hXiRnW_L98d4GQ",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if err != nil {
				t.Errorf("❌: err != nil: %v", err)
			}
		},
	},
	fmt.Sprintf("failure(%s,jwa.ErrInvalidKeyReceived)", jwa.PS512): {
		alg:              jwa.PS512,
		key:              "invalidKey",
		signingInput:     "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
		signatureEncoded: "J5W09-rNx0pt5_HBiydR-vOluS6oD-RpYNa8PVWwMcBDQSXiw6-EPW8iSsalXPspGj3ouQjAnOP_4-zrlUUlvUIt2T79XyNeiKuooyIFvka3Y5NnGiOUBHWvWcWp4RcQFMBrZkHtJM23sB5D7Wxjx0-HFeNk-Y3UJgeJVhg5NaWXypLkC4y0ADrUBfGAxhvGdRdULZivfvzuVtv6AzW6NRuEE6DM9xpoWX_4here-yvLS2YPiBTZ8xbB3axdM99LhES-n52lVkiX5AWg2JJkEROZzLMpaacA_xlbUz_zbIaOaoqk8gB5oO7kI6sZej3QAdGigQy-hXiRnW_L98d4GQ",
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrInvalidKeyReceived) {
				t.Errorf("❌: err != jwa.ErrInvalidKeyReceived: %v", err)
			}
		},
	},
	//
	// none
	//
	fmt.Sprintf("failure(%s,jwa.ErrAlgorithmNoneIsNotSupported)", jwa.PS512): {
		alg: jwa.None,
		errHandler: func(t *testing.T, err error) { //nolint:thelper
			if !errors.Is(err, jwa.ErrAlgorithmNoneIsNotSupported) {
				t.Errorf("❌: err != jwa.ErrAlgorithmNoneIsNotSupported: %v", err)
			}
		},
	},
}

func TestJWSAlgorithm_Verify(t *testing.T) {
	t.Parallel()
	for name, testCase := range verifyTestCases {
		t, name, testCase := t, name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testCase.errHandler(t, jwa.JWS(testCase.alg).Verify(testCase.key, testCase.signingInput, testCase.signatureEncoded))
		})
	}
}
