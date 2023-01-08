package jws_test

import (
	"testing"

	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
	"github.com/kunitsuinc/util.go/pkg/jose/jws"
)

func TestVerify(t *testing.T) {
	t.Parallel()
	t.Run("success()", func(t *testing.T) {
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
		if err := jws.Verify(jwa.HS256, key, signingInput, signatureEncoded); err != nil {
			t.Errorf("❌: jws.Verify: err != nil: %v", err)
		}
	})
}
