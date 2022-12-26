package jws_test

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	x509z "github.com/kunitsuinc/util.go/pkg/crypto/x509"
	"github.com/kunitsuinc/util.go/pkg/jose/jws"
	"github.com/kunitsuinc/util.go/pkg/must"
	testz "github.com/kunitsuinc/util.go/pkg/test"
)

type testCaseVerify struct {
	JWT           string
	Header        string
	Payload       string
	Key           crypto.PublicKey
	ResultHandler func(t *testing.T, err error)
}

var testCasesVerify = map[string]testCaseVerify{
	"failure(jws.ErrInvalidTokenReceived)": {
		JWT: ``,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidTokenReceived) {
				t.Errorf("%s: err != jws.ErrInvalidTokenReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(header,base64.RawURLEncoding.DecodeString)": {
		JWT: `InvalidHeader$.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			const expect = `illegal base64 data at input byte`
			if err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("%s: err != %s: %v", t.Name(), expect, err)
			}
		},
	},
	"failure(header,json.Unmarshal)": {
		JWT: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCI.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			const expect = `unexpected end of JSON input`
			if err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("%s: err != %s: %v", t.Name(), expect, err)
			}
		},
	},
	"failure(signature,base64.RawURLEncoding.DecodeString)": {
		JWT:     `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.InvalidSignature$`,
		Header:  `{"alg":"HS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Key:     []byte(`your-256-bit-secret`),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			const expect = `illegal base64 data at input byte`
			if err == nil || !strings.Contains(err.Error(), expect) {
				t.Errorf("%s: err != %s: %v", t.Name(), expect, err)
			}
		},
	},
	"success(HS256)": {
		JWT:     `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
		Header:  `{"alg":"HS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Key:     []byte(`your-256-bit-secret`),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(HS256,jws.ErrInvalidKeyReceived)": {
		JWT:     `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
		Header:  `{"alg":"HS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(HS256,jws.ErrFailedToVerifySignature)": {
		JWT:     `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
		Header:  `{"alg":"HS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Key:     []byte(""),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrFailedToVerifySignature) {
				t.Errorf("%s: err != jws.ErrFailedToVerifySignature: %v", t.Name(), err)
			}
		},
	},
	"success(HS384)": {
		JWT:     `eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ`,
		Header:  `{"alg":"HS384","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Key:     []byte(`your-384-bit-secret`),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(HS384,jws.ErrFailedToVerifySignature)": {
		JWT:     `eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8aMsJp4VGY_Ia2s9iWrS8jARCggx0FDRn2FehblXyvGYRrVVbu3LkKKqx_MEuDjQ`,
		Header:  `{"alg":"HS384","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Key:     []byte(""),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrFailedToVerifySignature) {
				t.Errorf("%s: err != jws.ErrFailedToVerifySignature: %v", t.Name(), err)
			}
		},
	},
	"success(HS512)": {
		JWT:     `eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg`,
		Header:  `{"alg":"HS512","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Key:     []byte(`your-512-bit-secret`),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(HS512,jws.ErrFailedToVerifySignature)": {
		JWT:     `eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._MRZSQUbU6G_jPvXIlFsWSU-PKT203EdcU388r5EWxSxg8QpB3AmEGSo2fBfMYsOaxvzos6ehRm4CYO1MrdwUg`,
		Header:  `{"alg":"HS512","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		Key:     []byte(""),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrFailedToVerifySignature) {
				t.Errorf("%s: err != jws.ErrFailedToVerifySignature: %v", t.Name(), err)
			}
		},
	},
	"success(RS256)": {
		JWT:     `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ`,
		Header:  `{"alg":"RS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(RS256,jws.ErrInvalidKeyReceived)": {
		JWT:     `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ`,
		Header:  `{"alg":"RS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(RS256,rsa.ErrVerification)": {
		JWT:     `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmInvalid`,
		Header:  `{"alg":"RS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, rsa.ErrVerification) {
				t.Errorf("%s: err != rsa.ErrVerification: %v", t.Name(), err)
			}
		},
	},
	"success(RS384)": {
		JWT:     `eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ`,
		Header:  `{"alg":"RS384","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(RS384)": {
		JWT:     `eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ`,
		Header:  `{"alg":"RS384","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(RS512)": {
		JWT:     `eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ`,
		Header:  `{"alg":"RS512","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(RS512)": {
		JWT:     `eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ`,
		Header:  `{"alg":"RS512","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(ES256)": {
		JWT:     `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA`,
		Header:  `{"alg":"ES256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(ES256,jws.ErrInvalidKeyReceived)": {
		JWT:     `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA`,
		Header:  `{"alg":"ES256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(ES256,keySize)": {
		JWT:     `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Invalid`,
		Header:  `{"alg":"ES256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(ES256,jws.ErrFailedToVerifySignature)": {
		JWT:     `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wInvalid`,
		Header:  `{"alg":"ES256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey256BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrFailedToVerifySignature) {
				t.Errorf("%s: err != jws.ErrFailedToVerifySignature: %v", t.Name(), err)
			}
		},
	},
	"success(ES384)": {
		JWT:     `eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj`,
		Header:  `{"alg":"ES384","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey384BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(ES384,jws.ErrInvalidKeyReceived)": {
		JWT:     `eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj`,
		Header:  `{"alg":"ES384","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(ES512)": {
		JWT:     `eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk`,
		Header:  `{"alg":"ES512","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseECDSAPublicKeyPEM([]byte(testz.TestECDSAPublicKey521BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(ES512,jws.ErrInvalidKeyReceived)": {
		JWT:     `eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk`,
		Header:  `{"alg":"ES512","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(PS256)": {
		JWT:     `eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg`,
		Header:  `{"alg":"PS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(PS256,jws.ErrInvalidKeyReceived)": {
		JWT:     `eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg`,
		Header:  `{"alg":"PS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(PS256,rsa.ErrVerification)": {
		JWT:     `eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRInvalid`,
		Header:  `{"alg":"PS256","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, rsa.ErrVerification) {
				t.Errorf("%s: err != rsa.ErrVerification: %v", t.Name(), err)
			}
		},
	},
	"success(PS384)": {
		JWT:     `eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Lfe_aCQme_gQpUk9-6l9qesu0QYZtfdzfy08w8uqqPH_gnw-IVyQwyGLBHPFBJHMbifdSMxPjJjkCD0laIclhnBhowILu6k66_5Y2z78GHg8YjKocAvB-wSUiBhuV6hXVxE5emSjhfVz2OwiCk2bfk2hziRpkdMvfcITkCx9dmxHU6qcEIsTTHuH020UcGayB1-IoimnjTdCsV1y4CMr_ECDjBrqMdnontkqKRIM1dtmgYFsJM6xm7ewi_ksG_qZHhaoBkxQ9wq9OVQRGiSZYowCp73d2BF3jYMhdmv2JiaUz5jRvv6lVU7Quq6ylVAlSPxeov9voYHO1mgZFCY1kQ`,
		Header:  `{"alg":"PS384","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(PS384,jws.ErrInvalidKeyReceived)": {
		JWT:     `eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Lfe_aCQme_gQpUk9-6l9qesu0QYZtfdzfy08w8uqqPH_gnw-IVyQwyGLBHPFBJHMbifdSMxPjJjkCD0laIclhnBhowILu6k66_5Y2z78GHg8YjKocAvB-wSUiBhuV6hXVxE5emSjhfVz2OwiCk2bfk2hziRpkdMvfcITkCx9dmxHU6qcEIsTTHuH020UcGayB1-IoimnjTdCsV1y4CMr_ECDjBrqMdnontkqKRIM1dtmgYFsJM6xm7ewi_ksG_qZHhaoBkxQ9wq9OVQRGiSZYowCp73d2BF3jYMhdmv2JiaUz5jRvv6lVU7Quq6ylVAlSPxeov9voYHO1mgZFCY1kQ`,
		Header:  `{"alg":"PS384","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"success(PS512)": {
		JWT:     `eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.J5W09-rNx0pt5_HBiydR-vOluS6oD-RpYNa8PVWwMcBDQSXiw6-EPW8iSsalXPspGj3ouQjAnOP_4-zrlUUlvUIt2T79XyNeiKuooyIFvka3Y5NnGiOUBHWvWcWp4RcQFMBrZkHtJM23sB5D7Wxjx0-HFeNk-Y3UJgeJVhg5NaWXypLkC4y0ADrUBfGAxhvGdRdULZivfvzuVtv6AzW6NRuEE6DM9xpoWX_4here-yvLS2YPiBTZ8xbB3axdM99LhES-n52lVkiX5AWg2JJkEROZzLMpaacA_xlbUz_zbIaOaoqk8gB5oO7kI6sZej3QAdGigQy-hXiRnW_L98d4GQ`,
		Header:  `{"alg":"PS512","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM))),
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nil) {
				t.Errorf("%s: err != nil: %v", t.Name(), err)
			}
		},
	},
	"failure(PS512,jws.ErrInvalidKeyReceived)": {
		JWT:     `eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.J5W09-rNx0pt5_HBiydR-vOluS6oD-RpYNa8PVWwMcBDQSXiw6-EPW8iSsalXPspGj3ouQjAnOP_4-zrlUUlvUIt2T79XyNeiKuooyIFvka3Y5NnGiOUBHWvWcWp4RcQFMBrZkHtJM23sB5D7Wxjx0-HFeNk-Y3UJgeJVhg5NaWXypLkC4y0ADrUBfGAxhvGdRdULZivfvzuVtv6AzW6NRuEE6DM9xpoWX_4here-yvLS2YPiBTZ8xbB3axdM99LhES-n52lVkiX5AWg2JJkEROZzLMpaacA_xlbUz_zbIaOaoqk8gB5oO7kI6sZej3QAdGigQy-hXiRnW_L98d4GQ`,
		Header:  `{"alg":"PS512","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}`,
		Key:     0,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidKeyReceived) {
				t.Errorf("%s: err != jws.ErrInvalidKeyReceived: %v", t.Name(), err)
			}
		},
	},
	"failure(jws.ErrInvalidAlgorithm)": {
		JWT:     `eyJhbGciOiJJbnZhbGlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`,
		Header:  `{"alg":"Invalid","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrInvalidAlgorithm) {
				t.Errorf("%s: err != jws.ErrInvalidAlgorithm: %v", t.Name(), err)
			}
		},
	},
	"failure(none)": {
		JWT:     `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`,
		Header:  `{"alg":"none","typ":"JWT"}`,
		Payload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		ResultHandler: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, jws.ErrAlgorithmNoneIsNotSupported) {
				t.Errorf("%s: err != jws.ErrAlgorithmNoneIsNotSupported: %v", t.Name(), err)
			}
		},
	},
}

func TestVerify(t *testing.T) {
	t.Parallel()

	for testName, testCase := range testCasesVerify {
		t, k, v := t, testName, testCase
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			_, _, err := jws.VerifySignature(v.JWT, v.Key)
			v.ResultHandler(t, err)
		})
	}
}
