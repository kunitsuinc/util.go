package jws_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	x509z "github.com/kunitsuinc/util.go/pkg/crypto/x509"
	"github.com/kunitsuinc/util.go/pkg/jose"
	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
	"github.com/kunitsuinc/util.go/pkg/jose/jwk"
	"github.com/kunitsuinc/util.go/pkg/jose/jws"
	"github.com/kunitsuinc/util.go/pkg/must"
	testz "github.com/kunitsuinc/util.go/pkg/test"
)

func TestVerify(t *testing.T) {
	t.Parallel()

	publicKey := must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM)))
	privateKey := must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM)))

	t.Run("success(HS256)", func(t *testing.T) {
		t.Parallel()
		key := []byte("your-256-bit-secret")
		signingInput := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
		signatureEncodedExpected := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		signatureEncoded, err := jws.Sign(jwa.HS256, key, signingInput)
		if err != nil {
			t.Errorf("❌: jws.Sign: err != nil: %v", err)
		}
		if actual, expect := signatureEncoded, signatureEncodedExpected; actual != expect {
			t.Errorf("❌: jws.Sign: actual != expect: %v", actual)
		}
		jwt := signingInput + "." + signatureEncoded
		if _, err := jws.Verify(jws.UseKey(key), jwt); err != nil {
			t.Errorf("❌: jws.Verify: err != nil: %v", err)
		}
	})

	t.Run("success(RS256,JSONWebKey)", func(t *testing.T) {
		t.Parallel()
		publicKey := must.One(x509z.ParseRSAPublicKeyPEM([]byte(testz.TestRSAPublicKey2048BitPEM)))
		privateKey := must.One(x509z.ParseRSAPrivateKeyPEM([]byte(testz.TestRSAPrivateKey2048BitPEM)))
		header := jose.NewHeader(
			jose.WithAlgorithm(jwa.RS256),
			jose.WithJSONWebKey(new(jwk.JSONWebKey).EncodeRSAPublicKey(publicKey)),
		)
		headerEncoded, err := header.Encode()
		if err != nil {
			t.Fatalf("❌: header.Encode: err != nil: %v", err)
		}
		payloadEncoded := "claims"
		signingInput := headerEncoded + "." + payloadEncoded

		signatureEncoded, err := jws.Sign(jwa.RS256, privateKey, signingInput)
		if err != nil {
			t.Fatalf("❌: jws.Sign: err != nil: %v", err)
		}

		if _, err := jws.Verify(jws.UseJSONWebKey(), signingInput+"."+signatureEncoded); err != nil {
			t.Fatalf("❌: jws.Verify: err != nil: %v", err)
		}
	})

	t.Run("success(RS256,JWKSetURL)", func(t *testing.T) {
		t.Parallel()
		mux := http.NewServeMux()
		fn, err := jwk.HandlerFunc(&jwk.JWKSet{Keys: []*jwk.JSONWebKey{
			new(jwk.JSONWebKey).EncodeRSAPublicKey(publicKey, jwk.WithKeyID("testKeyID")),
			new(jwk.JSONWebKey).EncodeRSAPublicKey(publicKey, jwk.WithKeyID("testKeyID2")),
		}})
		if err != nil {
			t.Fatalf("❌: jwk.HandlerFunc: err != nil: %v", err)
		}
		const keysPath = "/keys"
		mux.HandleFunc(keysPath, fn)
		s := httptest.NewServer(mux)
		jwksURL := s.URL + keysPath

		headerEncoded, err := jose.NewHeader(jose.WithAlgorithm(jwa.RS256), jose.WithJWKSetURL(jwksURL), jose.WithKeyID("testKeyID")).Encode()
		if err != nil {
			t.Fatalf("❌: header.Encode: err != nil: %v", err)
		}
		payloadEncoded := "claims"
		signingInput := headerEncoded + "." + payloadEncoded

		signatureEncoded, err := jws.Sign(jwa.RS256, privateKey, signingInput)
		if err != nil {
			t.Fatalf("❌: jws.Sign: err != nil: %v", err)
		}

		if _, err := jws.Verify(jws.UseJWKSetURL(context.Background()), signingInput+"."+signatureEncoded); err != nil {
			t.Fatalf("❌: jws.Verify: err != nil: %v", err)
		}
	})

	t.Run("failure(jws.ErrInvalidTokenReceived)", func(t *testing.T) {
		t.Parallel()
		if _, err := jws.Verify(jws.UseKey(nil), "invalidJWT"); err == nil || !errors.Is(err, jws.ErrInvalidTokenReceived) {
			t.Fatalf("❌: jws.Verify: err != jws.ErrInvalidTokenReceived: %v", err)
		}
	})

	t.Run("failure(jws.ErrInvalidTokenReceived)", func(t *testing.T) {
		t.Parallel()
		expect := "illegal base64 data at input byte 3"
		if _, err := jws.Verify(jws.UseKey(nil), "inv@lid.jwt.signature"); err == nil || !strings.Contains(err.Error(), expect) {
			t.Fatalf("❌: jws.Verify: err != %s: %v", expect, err)
		}
	})

	t.Run("failure(jws.ErrInvalidKeyOption)", func(t *testing.T) {
		t.Parallel()
		if _, err := jws.Verify(jws.UseKey(nil), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.jwt"); err == nil || !errors.Is(err, jws.ErrInvalidKeyOption) {
			t.Fatalf("❌: jws.Verify: err != jws.ErrInvalidKeyOption: %v", err)
		}
	})

	t.Run("failure(jose.ErrJSONWebKeyIsEmpty)", func(t *testing.T) {
		t.Parallel()
		_, err := jws.Verify(jws.UseJSONWebKey(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.jwt")
		if err == nil || !errors.Is(err, jose.ErrJSONWebKeyIsEmpty) {
			t.Fatalf("❌: jws.Verify: err != jose.ErrJSONWebKeyIsEmpty: %v", err)
		}
	})

	t.Run("failure(jwk.ErrKeyIsNotForAlgorithm)", func(t *testing.T) {
		t.Parallel()
		headerEncoded, err := jose.NewHeader(jose.WithAlgorithm(jwa.HS256), jose.WithJSONWebKey(new(jwk.JSONWebKey).EncodeRSAPublicKey(&rsa.PublicKey{N: big.NewInt(0)}))).Encode()
		if err != nil {
			t.Fatalf("Encode: err != nil: %v", err)
		}

		if _, err := jws.Verify(jws.UseJSONWebKey(), headerEncoded+".invalid.jwt"); err == nil || !errors.Is(err, jwk.ErrKeyIsNotForAlgorithm) {
			t.Fatalf("❌: jws.Verify: err != jwk.ErrKeyIsNotForAlgorithm: %v", err)
		}
	})

	t.Run("failure(jose.ErrJWKSetIsEmpty)", func(t *testing.T) {
		t.Parallel()
		if _, err := jws.Verify(jws.UseJWKSetURL(context.Background()), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.jwt"); err == nil || !errors.Is(err, jose.ErrJWKSetIsEmpty) {
			t.Fatalf("❌: jws.Verify: err != jose.ErrJWKSetIsEmpty: %v", err)
		}
	})

	t.Run("failure(jose.ErrJWKSetIsEmpty)", func(t *testing.T) {
		t.Parallel()
		headerEncoded, err := jose.NewHeader(jose.WithAlgorithm(jwa.HS256), jose.WithJWKSetURL("http://127.0.0.1:1/")).Encode()
		if err != nil {
			t.Fatalf("Encode: err != nil: %v", err)
		}
		expect := "connect: connection refused"
		if _, err := jws.Verify(jws.UseJWKSetURL(context.Background()), headerEncoded+".invalid.jwt"); err == nil || !strings.Contains(err.Error(), expect) {
			t.Fatalf("❌: jws.Verify: err != jose.ErrJWKSetIsEmpty: %v", err)
		}
	})

	t.Run("failure(jwk.ErrKeyIsNotForAlgorithm)", func(t *testing.T) {
		t.Parallel()
		mux := http.NewServeMux()
		fn, err := jwk.HandlerFunc(&jwk.JWKSet{Keys: []*jwk.JSONWebKey{
			new(jwk.JSONWebKey).EncodeRSAPublicKey(&rsa.PublicKey{N: big.NewInt(0)}),
		}})
		if err != nil {
			t.Fatalf("❌: jwk.HandlerFunc: err != nil: %v", err)
		}
		const keysPath = "/keys"
		mux.HandleFunc(keysPath, fn)
		s := httptest.NewServer(mux)
		jwksURL := s.URL + keysPath

		headerEncoded, err := jose.NewHeader(jose.WithAlgorithm(jwa.HS256), jose.WithJWKSetURL(jwksURL)).Encode()
		if err != nil {
			t.Fatalf("❌: header.Encode: err != nil: %v", err)
		}

		if _, err := jws.Verify(jws.UseJWKSetURL(context.Background()), headerEncoded+".invalid.jwt"); err == nil || !errors.Is(err, jwk.ErrKeyIsNotForAlgorithm) {
			t.Fatalf("❌: jws.Verify: err != jwk.ErrKeyIsNotForAlgorithm: %v", err)
		}
	})

	t.Run("failure(jwk.ErrKidNotFound)", func(t *testing.T) {
		t.Parallel()
		mux := http.NewServeMux()
		fn, err := jwk.HandlerFunc(&jwk.JWKSet{Keys: []*jwk.JSONWebKey{
			new(jwk.JSONWebKey).EncodeRSAPublicKey(publicKey, jwk.WithKeyID("testKeyID1")),
			new(jwk.JSONWebKey).EncodeRSAPublicKey(publicKey, jwk.WithKeyID("testKeyID2")),
		}})
		if err != nil {
			t.Fatalf("❌: jwk.HandlerFunc: err != nil: %v", err)
		}
		const keysPath = "/keys"
		mux.HandleFunc(keysPath, fn)
		s := httptest.NewServer(mux)
		jwksURL := s.URL + keysPath

		headerEncoded, err := jose.NewHeader(jose.WithAlgorithm(jwa.RS256), jose.WithJWKSetURL(jwksURL), jose.WithKeyID("NotFound")).Encode()
		if err != nil {
			t.Fatalf("❌: header.Encode: err != nil: %v", err)
		}

		if _, err := jws.Verify(jws.UseJWKSetURL(context.Background()), headerEncoded+".invalid.jwt"); err == nil || !errors.Is(err, jwk.ErrKidNotFound) {
			t.Fatalf("❌: jws.Verify: err != jwk.ErrKidNotFound: %v", err)
		}
	})
}
