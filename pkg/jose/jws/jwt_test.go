package jws_test

// func TestJWT(t *testing.T) {
// 	t.Parallel()

// 	hmacKey := []byte("key")

// 	t.Run("success()", func(t *testing.T) {
// 		t.Parallel()
// 		token, err := jws.NewToken(jose.NewHeader(jose.WithAlgorithm(jwa.HS256)), jwt.NewClaimsSet(), hmacKey)
// 		if err != nil {
// 			t.Fatalf("❌: jws.NewToken: %v", err)
// 		}
// 		if err := jws.Verify(token, hmacKey); err != nil {
// 			t.Fatalf("jws.VerifySignature: %v", err)
// 		}
// 		t.Logf("✅: token: %s", token)
// 	})

// 	t.Run("failure(header=nil)", func(t *testing.T) {
// 		t.Parallel()
// 		_, err := jws.NewToken(nil, jwt.NewClaimsSet(), hmacKey)
// 		if actual, expect := err, jws.ErrHeaderIsNil; !errors.Is(actual, expect) {
// 			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
// 		}
// 	})

// 	t.Run("failure(header)", func(t *testing.T) {
// 		t.Parallel()
// 		_, err := jws.NewToken(jose.NewHeader(jose.WithAlgorithm("none"), jose.WithPrivateHeaderParameter("invalid", func() {})), jwt.NewClaimsSet(), hmacKey)
// 		if actual, expect := err.Error(), "json: error calling MarshalJSON for type *jws.Header"; !strings.Contains(actual, expect) {
// 			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
// 		}
// 	})

// 	t.Run("failure(payload)", func(t *testing.T) {
// 		t.Parallel()
// 		_, err := jws.NewToken(jose.NewHeader(jose.WithAlgorithm(jwa.HS256)), jwt.NewClaimsSet(jwt.WithPrivateClaim("invalid", func() {})), hmacKey)
// 		if actual, expect := err.Error(), "json: error calling MarshalJSON for type *jwt.Claims"; !strings.Contains(actual, expect) {
// 			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
// 		}
// 	})

// 	t.Run("failure(Sign)", func(t *testing.T) {
// 		t.Parallel()
// 		_, err := jws.NewToken(jose.NewHeader(jose.WithAlgorithm(jwa.HS256)), jwt.NewClaimsSet(), "invalid key")
// 		if actual, expect := err, jws.ErrInvalidKeyReceived; !errors.Is(actual, expect) {
// 			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
// 		}
// 	})
// }
