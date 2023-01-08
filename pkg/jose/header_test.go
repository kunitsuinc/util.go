package jose //nolint:testpackage

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/kunitsuinc/util.go/pkg/discard"
	"github.com/kunitsuinc/util.go/pkg/jose/jwa"
	"github.com/kunitsuinc/util.go/pkg/jose/jwk"
	"github.com/kunitsuinc/util.go/pkg/must"
	testz "github.com/kunitsuinc/util.go/pkg/test"
)

const (
	testPrivatePrivateHeaderParameter1Key = "name"
	testPrivateHeaderParameter1Value      = "value"
)

var (
	_pub = must.One(x509.ParsePKIXPublicKey(discard.One(pem.Decode([]byte(testz.TestRSAPublicKey2048BitPEM))).Bytes)).(*rsa.PublicKey) //nolint:forcetypeassert
	_jwk = &jwk.JSONWebKey{
		KeyType:      "JWT",
		PublicKeyUse: "sig",
		KeyID:        "testKeyID",
		Algorithm:    "RS256",
		N:            base64.RawURLEncoding.EncodeToString(_pub.N.Bytes()),
		E:            base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(int64(_pub.E), 10))),
	}
	_x5c = []string{
		"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",
	}
	testHeader = &Header{
		Algorithm:                       string(jwa.HS256),
		JwksURL:                         "http://localhost/jwks",
		JSONWebKey:                      _jwk,
		KeyID:                           "testKeyID",
		X509URL:                         "http://localhost/x5u",
		X509CertificateChain:            _x5c,
		X509CertificateSHA1Thumbprint:   "x5t",
		X509CertificateSHA256Thumbprint: "x5t#S256",
		Type:                            "JWT",
		ContentType:                     "JWT",
		Critical:                        []string{"name"},
		PrivateHeaderParameters: map[string]interface{}{
			testPrivatePrivateHeaderParameter1Key: testPrivateHeaderParameter1Value,
		},
	}
	testHeaderString  = fmt.Sprintf(`{"alg":"HS256","jku":"http://localhost/jwks","jwk":{"kty":"JWT","use":"sig","alg":"RS256","kid":"testKeyID","n":"u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw","e":"NjU1Mzc"},"kid":"testKeyID","x5u":"http://localhost/x5u","x5c":["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"],"x5t":"x5t","x5t#S256":"x5t#S256","typ":"JWT","cty":"JWT","crit":["name"],"%s":"%s"}`, testPrivatePrivateHeaderParameter1Key, testPrivateHeaderParameter1Value)
	testHeaderEncoded = `eyJhbGciOiJIUzI1NiIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3QvandrcyIsImp3ayI6eyJrdHkiOiJKV1QiLCJ1c2UiOiJzaWciLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3RLZXlJRCIsIm4iOiJ1MVNVMUxmVkxQSENvek14SDJNbzRsZ09FZVB6Tm0wdFJnZUxlelY2ZmZBdDBndW5WVEx3N29uTFJucnEwX0l6Vzd5V1I3UWtybUJMN2pUS0VuNXUtcUtoYndLZkJzdElzLWJNWTJaa3AxOGduVHhLTHhvUzJ0RmN6R2tQTFBnaXpza3VlbU1naFJuaVdhb0xjeWVoa2QzcXFHRWx2V19WREw1QWFXVGcwbkxWa2pSbzl6LTQwUlF6dVZhRThBa0FGbXhaem93M3gtVkpZS2RqeWtrSjBpVDl3Q1MwRFJUWHUyNjlWMjY0VmZfM2p2cmVkWmlLUmtnd2xMOXhOQXd4WEZnMHhfWEZ3MDA1VVdWUklrZGdjS1dUanBCUDJkUHdWWjRXV0MtOWFHVmQtR3luMW8wQ0xlbGY0ckVqR29YYkFBRWdBcWVHVXhyY0lsYmpYZmJjbXciLCJlIjoiTmpVMU16YyJ9LCJraWQiOiJ0ZXN0S2V5SUQiLCJ4NXUiOiJodHRwOi8vbG9jYWxob3N0L3g1dSIsIng1YyI6WyJNSUlFM2pDQ0E4YWdBd0lCQWdJQ0F3RXdEUVlKS29aSWh2Y05BUUVGQlFBd1l6RUxNQWtHQTFVRUJoTUNWVk14SVRBZkJnTlZCQW9UR0ZSb1pTQkhieUJFWVdSa2VTQkhjbTkxY0N3Z1NXNWpMakV4TUM4R0ExVUVDeE1vUjI4Z1JHRmtaSGtnUTJ4aGMzTWdNaUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVUQWVGdzB3TmpFeE1UWXdNVFUwTXpkYUZ3MHlOakV4TVRZd01UVTBNemRhTUlIS01Rc3dDUVlEVlFRR0V3SlZVekVRTUE0R0ExVUVDQk1IUVhKcGVtOXVZVEVUTUJFR0ExVUVCeE1LVTJOdmRIUnpaR0ZzWlRFYU1CZ0dBMVVFQ2hNUlIyOUVZV1JrZVM1amIyMHNJRWx1WXk0eE16QXhCZ05WQkFzVEttaDBkSEE2THk5alpYSjBhV1pwWTJGMFpYTXVaMjlrWVdSa2VTNWpiMjB2Y21Wd2IzTnBkRzl5ZVRFd01DNEdBMVVFQXhNblIyOGdSR0ZrWkhrZ1UyVmpkWEpsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUkV3RHdZRFZRUUZFd2d3TnprMk9USTROekNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNUXQxUldNbkNaTTdESTE2MSs0V1FGYXBtR0JXVHR3WTZ2ajNEM0hLcmpKTTlONTVEcnRQREFqaEk2ek1CUzJzb2ZEUFpWVUJKN2ZtZDBMSlI0aDNtVXBmaldvcVZUcjl2Y3lPZFFtVlpXdDcvditXSWJYbnZRQWpZd3FETDFDQk02blB3VDI3b0R5cXU5U29XbG0ycjRhclYzYUxHYnFHbXU3NVJwUlNnQXZTTWVZZGRpNUtjanUrR1p0Q3B5ejgveDRmS0w0by9LMXcvTzVlcEhCcCtZbExweW83UkpsYm1yMkVrUlRjRENWdzV3cldDczlDSFJLOHI1UnNMK0gwRXduV0d1MU5jV2RyeGN4K0F1UDdxMkJOZ1dKQ0pqUE9xOGxoOEJKNnFmOVovZEZqcGZNRkRuaU5vVzFmaG8zL1JiMmNSR2FkREFXL2hPVW96K0VEVThDQXdFQUFhT0NBVEl3Z2dFdU1CMEdBMVVkRGdRV0JCVDlyR0V5azJ4RjF1THVoVithdXVkMm1Xak01ekFmQmdOVkhTTUVHREFXZ0JUU3hMRFNrZFJNRVhHelljczlvZjdkcUdyVTR6QVNCZ05WSFJNQkFmOEVDREFHQVFIL0FnRUFNRE1HQ0NzR0FRVUZCd0VCQkNjd0pUQWpCZ2dyQmdFRkJRY3dBWVlYYUhSMGNEb3ZMMjlqYzNBdVoyOWtZV1JrZVM1amIyMHdSZ1lEVlIwZkJEOHdQVEE3b0RtZ040WTFhSFIwY0RvdkwyTmxjblJwWm1sallYUmxjeTVuYjJSaFpHUjVMbU52YlM5eVpYQnZjMmwwYjNKNUwyZGtjbTl2ZEM1amNtd3dTd1lEVlIwZ0JFUXdRakJBQmdSVkhTQUFNRGd3TmdZSUt3WUJCUVVIQWdFV0ttaDBkSEE2THk5alpYSjBhV1pwWTJGMFpYTXVaMjlrWVdSa2VTNWpiMjB2Y21Wd2IzTnBkRzl5ZVRBT0JnTlZIUThCQWY4RUJBTUNBUVl3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQU5LR3dPeTkrYUcyWis1bUM2SUdPZ1JRamhWeXJFcDBsVlBMTjh0RVNlOEhrR3N6Mlpid2xGYWxFekFGUElVeUlYdkp4d3FvSktTUTNrYlRKU01VQTJmQ0VOWnZEMTE3ZXN5ZnhWZ3F3Y1NlSWFoYTg2eWtSdk9lNUdQTEw1Q2tLU2tCMlhJc0tkODNBU2U4VCs1bzB5R1B3TFBrOVFudDBoQ3FVN1MrOE14WkM5WTdsaHlWSkVuZnp1ejlwMGlSRkVVT09qWnYya1d6UmFKQnlkVFhSRTQrdVhSMjFhSVRWU3pHaDZPMW1hd0doSWQvZFFiOHZ4Uk1Ec3h1eE44OXR4Sng5T2p4VVVBaUtFbmdIVXVIcURUTUJxTGRFbHJSaGpaa0F6VnZiM2R1Ni9LRlVKaGVxd05UclpFall4OFduTTI1c2dWak91SDBhQnNYQlRXVlUrND0iLCJNSUlFK3pDQ0JHU2dBd0lCQWdJQ0FRMHdEUVlKS29aSWh2Y05BUUVGQlFBd2dic3hKREFpQmdOVkJBY1RHMVpoYkdsRFpYSjBJRlpoYkdsa1lYUnBiMjRnVG1WMGQyOXlhekVYTUJVR0ExVUVDaE1PVm1Gc2FVTmxjblFzSUVsdVl5NHhOVEF6QmdOVkJBc1RMRlpoYkdsRFpYSjBJRU5zWVhOeklESWdVRzlzYVdONUlGWmhiR2xrWVhScGIyNGdRWFYwYUc5eWFYUjVNU0V3SHdZRFZRUURFeGhvZEhSd09pOHZkM2QzTG5aaGJHbGpaWEowTG1OdmJTOHhJREFlQmdrcWhraUc5dzBCQ1FFV0VXbHVabTlBZG1Gc2FXTmxjblF1WTI5dE1CNFhEVEEwTURZeU9URTNNRFl5TUZvWERUSTBNRFl5T1RFM01EWXlNRm93WXpFTE1Ba0dBMVVFQmhNQ1ZWTXhJVEFmQmdOVkJBb1RHRlJvWlNCSGJ5QkVZV1JrZVNCSGNtOTFjQ3dnU1c1akxqRXhNQzhHQTFVRUN4TW9SMjhnUkdGa1pIa2dRMnhoYzNNZ01pQkRaWEowYVdacFkyRjBhVzl1SUVGMWRHaHZjbWwwZVRDQ0FTQXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRU5BRENDQVFnQ2dnRUJBTjZkMStwWEdFbWhXK3ZYWDBpRzZyN2QvK1R2Wnh6MFpXaXpWM0dnWG5lNzdadEo2WENBUFZZWVl3aHYydkxNMEQ5L0FsUWlWQkRZc29IVXdIVTlTMy9IZDhNK2VLc2FBN1VnYXk5cUs3SEZpSDdFdXg2d3dkaEZKMitxTjFqM2h5YlgyQzMycVJlM0gzSTJUcVlYUDJXWWt0c3FibDJpL29qZ0M5NS81WTBWNGV2TE90WGlFcUlUTGRpT3IxOFNQYUFJQlFpMlhLVmxPQVJGbVI2allHQjB4VUdsY21JYllzVWZiMThhUXI0Q1VXV29yaU1ZYXZ4NEE2bE5mNEREK3F0YS9LRkFwTW9aRnY2eXlPOWVjdzN1ZDcyYTlubVl2TEVIWjZJVkRkMmdXTVpFZXdvK1lpaGZ1a0VIVTFqUEVYNDRkTVg0LzdWcGtJK0VkT3FYRzY4Q0FRT2pnZ0hoTUlJQjNUQWRCZ05WSFE0RUZnUVUwc1N3MHBIVVRCRnhzMkhMUGFIKzNhaHExT013Z2RJR0ExVWRJd1NCeWpDQng2R0J3YVNCdmpDQnV6RWtNQ0lHQTFVRUJ4TWJWbUZzYVVObGNuUWdWbUZzYVdSaGRHbHZiaUJPWlhSM2IzSnJNUmN3RlFZRFZRUUtFdzVXWVd4cFEyVnlkQ3dnU1c1akxqRTFNRE1HQTFVRUN4TXNWbUZzYVVObGNuUWdRMnhoYzNNZ01pQlFiMnhwWTNrZ1ZtRnNhV1JoZEdsdmJpQkJkWFJvYjNKcGRIa3hJVEFmQmdOVkJBTVRHR2gwZEhBNkx5OTNkM2N1ZG1Gc2FXTmxjblF1WTI5dEx6RWdNQjRHQ1NxR1NJYjNEUUVKQVJZUmFXNW1iMEIyWVd4cFkyVnlkQzVqYjIyQ0FRRXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QXpCZ2dyQmdFRkJRY0JBUVFuTUNVd0l3WUlLd1lCQlFVSE1BR0dGMmgwZEhBNkx5OXZZM053TG1kdlpHRmtaSGt1WTI5dE1FUUdBMVVkSHdROU1Ec3dPYUEzb0RXR00yaDBkSEE2THk5alpYSjBhV1pwWTJGMFpYTXVaMjlrWVdSa2VTNWpiMjB2Y21Wd2IzTnBkRzl5ZVM5eWIyOTBMbU55YkRCTEJnTlZIU0FFUkRCQ01FQUdCRlVkSUFBd09EQTJCZ2dyQmdFRkJRY0NBUllxYUhSMGNEb3ZMMk5sY25ScFptbGpZWFJsY3k1bmIyUmhaR1I1TG1OdmJTOXlaWEJ2YzJsMGIzSjVNQTRHQTFVZER3RUIvd1FFQXdJQkJqQU5CZ2txaGtpRzl3MEJBUVVGQUFPQmdRQzFRUG1uSGZicS9xUWFRbHBFOXhYVWhVYUp3TDZlNCtQcnhlTllpWStTbjFlb2NTeEkwWUd5ZVIrc0JqVVpzRTRPV0JzVXM1aUIwUVFleUFmSmc1OTRSQW9ZQzVqY2RucGxEUTF0Z01RTEFSekxyVWMrY2I1M1M4d0dkOUQwVm1zZlN4T2FGSXFJSTZoUjhJTk1xelcvUm40NTNIV2tydWdwKys4NWowOVZadz09IiwiTUlJQzV6Q0NBbEFDQVFFd0RRWUpLb1pJaHZjTkFRRUZCUUF3Z2JzeEpEQWlCZ05WQkFjVEcxWmhiR2xEWlhKMElGWmhiR2xrWVhScGIyNGdUbVYwZDI5eWF6RVhNQlVHQTFVRUNoTU9WbUZzYVVObGNuUXNJRWx1WXk0eE5UQXpCZ05WQkFzVExGWmhiR2xEWlhKMElFTnNZWE56SURJZ1VHOXNhV041SUZaaGJHbGtZWFJwYjI0Z1FYVjBhRzl5YVhSNU1TRXdId1lEVlFRREV4aG9kSFJ3T2k4dmQzZDNMblpoYkdsalpYSjBMbU52YlM4eElEQWVCZ2txaGtpRzl3MEJDUUVXRVdsdVptOUFkbUZzYVdObGNuUXVZMjl0TUI0WERUazVNRFl5TmpBd01UazFORm9YRFRFNU1EWXlOakF3TVRrMU5Gb3dnYnN4SkRBaUJnTlZCQWNURzFaaGJHbERaWEowSUZaaGJHbGtZWFJwYjI0Z1RtVjBkMjl5YXpFWE1CVUdBMVVFQ2hNT1ZtRnNhVU5sY25Rc0lFbHVZeTR4TlRBekJnTlZCQXNUTEZaaGJHbERaWEowSUVOc1lYTnpJRElnVUc5c2FXTjVJRlpoYkdsa1lYUnBiMjRnUVhWMGFHOXlhWFI1TVNFd0h3WURWUVFERXhob2RIUndPaTh2ZDNkM0xuWmhiR2xqWlhKMExtTnZiUzh4SURBZUJna3Foa2lHOXcwQkNRRVdFV2x1Wm05QWRtRnNhV05sY25RdVkyOXRNSUdmTUEwR0NTcUdTSWIzRFFFQkFRVUFBNEdOQURDQmlRS0JnUURPT25ISzVhdklXWkpWMTZ2WWRBNzU3dG4yVlVkWlpVY09CVlhjNjVnMlBGeFRYZE13enpqc3ZVR0o3U1ZDQ1NSckNsNnpmTjFTTFV6bTFOWjlXbG1wWmRSSkV5MGtUUnhRYjdYQmhWUTcvbkhrMDF4QytZRGdrUm9LV3prMlovTS9WWHdiUDdSZlpITTA0N1FTdjRkaytOb1MvemNud2JORHUrOTdiaTVwOXdJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQlFVQUE0R0JBRHQvVUc5dlVKU1pTV0k0T0I5TCtLWElQcWVDZ2ZZcngrakZ6dWc2RUlMTEdBQ09UYjJvV0graGVRQzF1K21OcjBIWkR6VHVJWUVab0RKSktQVEVqbGJWVWpQOVVOVittV3dENU1sTS9NdHNxMmF6U2lHTTViVU1NajRRc3N4c29keWFtRXdDVy9QT3VaNmxjZzVLdHo4ODVoWm8rTDd0ZEV5OFc5VmlIMFBkIl0sIng1dCI6Ing1dCIsIng1dCNTMjU2IjoieDV0I1MyNTYiLCJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJjcml0IjpbIm5hbWUiXSwibmFtZSI6InZhbHVlIn0`
)

func TestHeader_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("success()", func(t *testing.T) {
		t.Parallel()

		header := new(Header)
		if err := json.Unmarshal([]byte(testHeaderString), header); err != nil {
			t.Fatalf("❌: json.Unmarshal: err != nil: %v", err)
		}
		v, ok := header.PrivateHeaderParameters[testPrivatePrivateHeaderParameter1Key]
		if !ok {
			t.Fatalf("❌: header.PrivateHeaderParameters[testPrivatePrivateHeaderParameter1Key]: want(%T) != got(%T)", v, header.PrivateHeaderParameters[testPrivatePrivateHeaderParameter1Key])
		}
		if actual, expect := v, testPrivateHeaderParameter1Value; actual != expect {
			t.Fatalf("❌: actual != expect: %v != %v", actual, expect)
		}
		t.Logf("✅: header: %#v", header)
	})
}

func TestHeader_MarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("success()", func(t *testing.T) {
		t.Parallel()
		h := NewHeader(
			WithAlgorithm(string(jwa.HS256)),
			WithJwksURL("http://localhost/jwks"),
			WithJSONWebKey(_jwk),
			WithKeyID("testKeyID"),
			WithX509URL("http://localhost/x5u"),
			WithX509CertificateChain(_x5c),
			WithX509CertificateSHA1Thumbprint("x5t"),
			WithX509CertificateSHA256Thumbprint("x5t#S256"),
			WithType("JWT"),
			WithContentType("JWT"),
			WithCritical([]string{"name"}),
			WithPrivateHeaderParameter(testPrivatePrivateHeaderParameter1Key, testPrivateHeaderParameter1Value),
		)
		actual, err := json.Marshal(h)
		if err != nil {
			t.Fatalf("❌: err != nil: %v", err)
		}
		if expect := []byte(testHeaderString); !bytes.Equal(actual, expect) {
			t.Fatalf("❌: expect != actual: %s != %s", actual, expect)
		}
	})

	t.Run("success(len(PrivateHeaderParameters)==0)", func(t *testing.T) {
		t.Parallel()
		b, err := json.Marshal(NewHeader(WithAlgorithm(string(jwa.HS256))))
		if err != nil {
			t.Fatalf("❌: json.Marshal: %v", err)
		}
		if expect, actual := `{"alg":"HS256"}`, string(b); expect != actual {
			t.Fatalf("❌: expect != actual: %v != %v", expect, actual)
		}
		t.Logf("✅: header: %s", b)
	})
}

func TestHeader_marshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("failure(json_Marshal)", func(t *testing.T) {
		t.Parallel()
		_, err := testHeader.marshalJSON(
			func(v any) ([]byte, error) { return nil, testz.ErrTestError },
			bytes.HasSuffix,
			bytes.HasPrefix,
		)
		if !errors.Is(err, testz.ErrTestError) {
			t.Fatalf("❌: err != testz.ErrTestError: %v", err)
		}
	})

	t.Run("failure(invalid)", func(t *testing.T) {
		t.Parallel()
		h := &Header{
			PrivateHeaderParameters: map[string]any{
				"invalid": func() {},
			},
		}
		_, err := h.marshalJSON(
			json.Marshal,
			bytes.HasSuffix,
			bytes.HasPrefix,
		)
		if err == nil {
			t.Fatalf("❌: err == nil: %v", err)
		}
		if expect, actual := "invalid private header parameters", err.Error(); !strings.Contains(actual, expect) {
			t.Fatalf("❌: expect != actual: %s != %s", expect, actual)
		}
	})

	t.Run("failure(bytes_HasSuffix)", func(t *testing.T) {
		t.Parallel()
		_, err := testHeader.marshalJSON(
			json.Marshal,
			func(s, suffix []byte) bool { return false },
			bytes.HasPrefix,
		)
		if !errors.Is(err, ErrInvalidJSON) {
			t.Fatalf("❌: err != ErrInvalidJSON: %v", err)
		}
	})

	t.Run("failure(bytes_HasPrefix)", func(t *testing.T) {
		t.Parallel()
		_, err := testHeader.marshalJSON(
			json.Marshal,
			bytes.HasSuffix,
			func(s, suffix []byte) bool { return false },
		)
		if !errors.Is(err, ErrInvalidJSON) {
			t.Fatalf("❌: err != ErrInvalidJSON: %v", err)
		}
	})
}

func TestHeader_Encode(t *testing.T) {
	t.Parallel()

	t.Run("success()", func(t *testing.T) {
		t.Parallel()
		actual, err := testHeader.Encode()
		if err != nil {
			t.Fatalf("❌: err != nil: %v", err)
		}
		if expect := testHeaderEncoded; expect != actual {
			t.Fatalf("❌: expect != actual: %s != %s", "", actual)
		}
	})

	t.Run("failure(json.Marshal)", func(t *testing.T) {
		t.Parallel()
		h := &Header{
			PrivateHeaderParameters: map[string]any{
				"invalid": func() {},
			},
		}
		_, err := h.Encode()
		if err == nil {
			t.Fatalf("❌: err == nil: %v", err)
		}
		if expect, actual := "invalid private header parameters", err.Error(); !strings.Contains(actual, expect) {
			t.Fatalf("❌: expect != actual: %s != %s", expect, actual)
		}
	})
}

func TestHeader_Decode(t *testing.T) {
	t.Parallel()

	t.Run("success()", func(t *testing.T) {
		t.Parallel()
		actual := new(Header)
		err := actual.Decode(testHeaderEncoded)
		if err != nil {
			t.Fatalf("❌: err != nil: %v", err)
		}
		if expect := testHeader; !reflect.DeepEqual(expect, actual) {
			t.Fatalf("❌: expect != actual: %v != %v", expect, actual)
		}
	})

	t.Run("failure(base64.RawURLEncoding.DecodeString)", func(t *testing.T) {
		t.Parallel()
		err := new(Header).Decode("inv@lid")
		if expect, actual := "illegal base64 data at input byte 3", err.Error(); !strings.Contains(actual, expect) {
			t.Fatalf("❌: expect != actual: %s != %s", expect, actual)
		}
	})

	t.Run("failure(json.Unmarshal)", func(t *testing.T) {
		t.Parallel()
		err := new(Header).Decode("aW52QGxpZA") // invalid (base64-encoded)
		if expect, actual := "invalid character 'i' looking for beginning of value", err.Error(); !strings.Contains(actual, expect) {
			t.Fatalf("❌: expect != actual: %s != %s", expect, actual)
		}
	})
}
