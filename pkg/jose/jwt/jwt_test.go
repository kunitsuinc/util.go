package jwt_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kunitsuinc/util.go/pkg/jose/jws"
	"github.com/kunitsuinc/util.go/pkg/jose/jwt"
)

var (
	testToken   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UifQ.LWG7yvgEiiKDUA2PmykvKGKMedYPyLWsLCcJR5pn-Kw"
	testHMACKey = []byte("your-256-bit-secret")
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("success()", func(t *testing.T) {
		t.Parallel()
		token, err := jwt.New(jwt.JWSEncoder(
			jws.NewHeader(
				"HS256",
				jws.WithType("JWT"),
			),
			jwt.NewClaims(
				jwt.WithSubject("1234567890"),
				jwt.WithPrivateClaim("name", "John Doe"),
				jwt.WithIssuedAt(time.Unix(1516239022, 0)),
			),
			testHMACKey,
		))
		if err != nil {
			t.Fatalf("❌: jwt.New: err != nil: %v", err)
		}
		t.Logf("✅: token: %s", token)
	})

	t.Run("failure(header=nil)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.New(jwt.JWSEncoder(nil, jwt.NewClaims(), testHMACKey))
		if actual, expect := err, jwt.ErrHeaderIsNil; !errors.Is(actual, expect) {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
	})

	t.Run("failure(header)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.New(jwt.JWSEncoder(jws.NewHeader("none", jws.WithPrivateHeaderParameter("invalid", func() {})), jwt.NewClaims(), testHMACKey))
		if actual, expect := err.Error(), "json: error calling MarshalJSON for type *jws.Header"; !strings.Contains(actual, expect) {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
	})

	t.Run("failure(payload)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.New(jwt.JWSEncoder(jws.NewHeader("HS256"), jwt.NewClaims(jwt.WithPrivateClaim("invalid", func() {})), testHMACKey))
		if actual, expect := err.Error(), "json: error calling MarshalJSON for type *jwt.Claims"; !strings.Contains(actual, expect) {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
	})

	t.Run("failure(Sign)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.New(jwt.JWSEncoder(jws.NewHeader("HS256"), jwt.NewClaims(), "invalid key"))
		if actual, expect := err, jws.ErrInvalidKeyReceived; !errors.Is(actual, expect) {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
	})
}

func TestVerify(t *testing.T) {
	t.Parallel()

	t.Run("success()", func(t *testing.T) {
		t.Parallel()

		err := jwt.Verify(jwt.JWSVerifier(testToken, testHMACKey, nil, nil))
		if err != nil {
			t.Fatalf("❌: err != nil: %v", err)
		}
	})
}
