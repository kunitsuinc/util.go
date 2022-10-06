package errorz_test

import (
	"testing"

	"github.com/kunitsuinc/util.go/errorz"
	"github.com/kunitsuinc/util.go/testz"
)

func TestContains(t *testing.T) {
	t.Parallel()
	t.Run("success(nil)", func(t *testing.T) {
		t.Parallel()
		err := (error)(nil)
		if errorz.Contains(err, "testz: test error") {
			t.Errorf("err not contain %s: %v", "testz: test error", err)
		}
	})

	t.Run("success(testz.ErrTestError)", func(t *testing.T) {
		t.Parallel()
		err := testz.ErrTestError
		if !errorz.Contains(err, "testz: test error") {
			t.Errorf("err not contain `%s`: %v", "testz: test error", err)
		}
	})
}
