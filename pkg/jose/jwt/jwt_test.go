package jwt_test

import (
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
		token, err := jwt.NewJWSToken(
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
			t.Fatalf("❌: jwt.NewJWSToken: err != nil: %v", err)
		}
		if _, _, err := jwt.Verify(jws.UseKey(hmacKey), token); err != nil {
			t.Fatalf("❌: jwt.Verify: err != nil: %v", err)
		}
	})
}
