package jwt_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kunitsuinc/util.go/pkg/jose"
	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
	"github.com/kunitsuinc/util.go/pkg/jose/jws"
	"github.com/kunitsuinc/util.go/pkg/jose/jwt"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("success()", func(t *testing.T) {
		t.Parallel()
		hmacKey := []byte("test")
		token, err := jwt.New(
			hmacKey,
			jose.NewHeader(
				jose.WithAlgorithm(jwa.HS256),
				jose.WithType("JWT"),
				jose.WithPrivateHeaderParameter("testPrivateHeaderParameter", "testPrivateHeaderParameter"),
			),
			jwt.NewClaimsSet(
				jwt.WithSubject("userID"),
				jwt.WithAudience("http://localhost/test/aud"),
				jwt.WithExpirationTime(time.Now().Add(1*time.Hour)),
				jwt.WithPrivateClaim("testPrivateClaim", "testPrivateClaim"),
			),
		)
		if err != nil {
			t.Errorf("❌: jwt.New: err != nil: %v", err)
		}
		if _, _, err := jwt.Verify(
			jws.UseKey(hmacKey),
			token,
			jwt.VerifyAudience("http://localhost/test/aud"),
			jwt.VerifyPrivateClaims(func(pc jwt.PrivateClaims) error {
				if _, ok := pc["testPrivateClaim"]; !ok {
					return errors.New("testPrivateClaim")
				}
				return nil
			}),
		); err != nil {
			t.Errorf("❌: jwt.Verify: err != nil: %v", err)
		}
	})

	t.Run("failure(header.Encode)", func(t *testing.T) {
		t.Parallel()
		hmacKey := []byte("test")
		_, err := jwt.New(
			hmacKey,
			jose.NewHeader(
				jose.WithAlgorithm(jwa.HS256),
				jose.WithType("JWT"),
				jose.WithPrivateHeaderParameter("testPrivateHeaderParameter", func() {}),
			),
			jwt.NewClaimsSet(
				jwt.WithSubject("userID"),
				jwt.WithAudience("http://localhost/test/aud"),
				jwt.WithExpirationTime(time.Now().Add(1*time.Hour)),
				jwt.WithPrivateClaim("testPrivateClaim", "testPrivateClaim"),
			),
		)
		if expect := "invalid private header parameters"; err == nil || !strings.Contains(err.Error(), expect) {
			t.Errorf("❌: jwt.New: err != %s: %v", expect, err)
		}
	})

	t.Run("failure(claimsSet.Encode)", func(t *testing.T) {
		t.Parallel()
		hmacKey := []byte("test")
		_, err := jwt.New(
			hmacKey,
			jose.NewHeader(
				jose.WithAlgorithm(jwa.HS256),
				jose.WithType("JWT"),
				jose.WithPrivateHeaderParameter("testPrivateHeaderParameter", "testPrivateHeaderParameter"),
			),
			jwt.NewClaimsSet(
				jwt.WithSubject("userID"),
				jwt.WithAudience("http://localhost/test/aud"),
				jwt.WithExpirationTime(time.Now().Add(1*time.Hour)),
				jwt.WithPrivateClaim("testPrivateClaim", func() {}),
			),
		)
		if expect := "invalid private claims"; err == nil || !strings.Contains(err.Error(), expect) {
			t.Errorf("❌: jwt.New: err != %s: %v", expect, err)
		}
	})

	t.Run("failure(jwa.ErrInvalidKeyReceived)", func(t *testing.T) {
		t.Parallel()
		_, err := jwt.New(
			nil,
			jose.NewHeader(
				jose.WithAlgorithm(jwa.HS256),
				jose.WithType("JWT"),
				jose.WithPrivateHeaderParameter("testPrivateHeaderParameter", "testPrivateHeaderParameter"),
			),
			jwt.NewClaimsSet(
				jwt.WithSubject("userID"),
				jwt.WithAudience("http://localhost/test/aud"),
				jwt.WithExpirationTime(time.Now().Add(1*time.Hour)),
				jwt.WithPrivateClaim("testPrivateClaim", "testPrivateClaim"),
			),
		)
		if err == nil || !errors.Is(err, jwa.ErrInvalidKeyReceived) {
			t.Errorf("❌: jwt.New: err != jwa.ErrInvalidKeyReceived: %v", err)
		}
	})
}

func TestVerify(t *testing.T) {
	t.Parallel()

	testHS256Key := []byte(`your-256-bit-secret`)
	testHS256JWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	t.Run("success()", func(t *testing.T) {
		t.Parallel()
		if _, _, err := jwt.Verify(jws.UseKey(testHS256Key), testHS256JWT); err != nil {
			t.Errorf("❌: jwt.Verify: err != nil: %v", err)
		}
	})
}
