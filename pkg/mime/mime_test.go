package mime_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kunitsuinc/util.go/pkg/mime"
	testz "github.com/kunitsuinc/util.go/pkg/test"
)

func TestDetectContentType(t *testing.T) {
	t.Parallel()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		const expect = "text/html; charset=utf-8"
		actual, err := mime.DetectContentType(strings.NewReader("<!DOCTYPE html>"))
		if err != nil {
			t.Errorf("err != nil: %v", err)
		}
		if expect != actual {
			t.Errorf("expect != actual: %v != %v", expect, actual)
		}
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		r := testz.NewReadWriter(bytes.NewBuffer(nil), 0, testz.ErrTestError)
		if _, err := mime.DetectContentType(r); err == nil {
			t.Errorf("err == nil")
		}
	})
}
