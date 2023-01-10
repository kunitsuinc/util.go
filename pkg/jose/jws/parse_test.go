package jws_test

import (
	"errors"
	"testing"

	"github.com/kunitsuinc/util.go/pkg/jose/jws"
)

func TestParse(t *testing.T) {
	t.Parallel()
	t.Run("success()", func(t *testing.T) {
		t.Parallel()
		jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		_, _, _, err := jws.Parse(jwt)
		if err != nil {
			t.Errorf("❌: jws.ParseHeader: err != nil: %v", err)
		}
	})
	t.Run("failure(jws.ErrInvalidTokenReceived)", func(t *testing.T) {
		t.Parallel()
		jwt := "invalidJWT"
		_, _, _, err := jws.Parse(jwt)
		if !errors.Is(err, jws.ErrInvalidTokenReceived) {
			t.Errorf("❌: jws.ParseHeader: err != jws.ErrInvalidTokenReceived: %v", err)
		}
	})
}
