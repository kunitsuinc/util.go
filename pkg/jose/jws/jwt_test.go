package jws_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kunitsuinc/util.go/pkg/jose"
	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
	"github.com/kunitsuinc/util.go/pkg/jose/jws"
	"github.com/kunitsuinc/util.go/pkg/jose/jwt"
)

func TestJWT(t *testing.T) {
	t.Parallel()

	hmacKey := []byte("key")

	t.Run("success()", func(t *testing.T) {
		t.Parallel()
		token, err := jws.NewToken(jose.NewHeader(jose.WithAlgorithm(jwa.HS256)), jwt.NewClaims(), hmacKey)
		if err != nil {
			t.Fatalf("❌: jws.NewToken: %v", err)
		}
		if err := jws.VerifySignature(token, hmacKey); err != nil {
			t.Fatalf("jws.VerifySignature: %v", err)
		}
		t.Logf("✅: token: %s", token)
	})

	t.Run("failure(header=nil)", func(t *testing.T) {
		t.Parallel()
		_, err := jws.NewToken(nil, jwt.NewClaims(), hmacKey)
		if actual, expect := err, jws.ErrHeaderIsNil; !errors.Is(actual, expect) {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
	})

	t.Run("failure(header)", func(t *testing.T) {
		t.Parallel()
		_, err := jws.NewToken(jose.NewHeader(jose.WithAlgorithm("none"), jose.WithPrivateHeaderParameter("invalid", func() {})), jwt.NewClaims(), hmacKey)
		if actual, expect := err.Error(), "json: error calling MarshalJSON for type *jws.Header"; !strings.Contains(actual, expect) {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
	})

	t.Run("failure(payload)", func(t *testing.T) {
		t.Parallel()
		_, err := jws.NewToken(jose.NewHeader(jose.WithAlgorithm(jwa.HS256)), jwt.NewClaims(jwt.WithPrivateClaim("invalid", func() {})), hmacKey)
		if actual, expect := err.Error(), "json: error calling MarshalJSON for type *jwt.Claims"; !strings.Contains(actual, expect) {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
	})

	t.Run("failure(Sign)", func(t *testing.T) {
		t.Parallel()
		_, err := jws.NewToken(jose.NewHeader(jose.WithAlgorithm(jwa.HS256)), jwt.NewClaims(), "invalid key")
		if actual, expect := err, jws.ErrInvalidKeyReceived; !errors.Is(actual, expect) {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
	})
}
