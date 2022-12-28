package jws

type JWS struct {
	header    *Header
	payload   string
	signature []byte

	rawToken string
	key      any

	verifyOption VerifyOption
}

type VerifyOption func(jws_ *JWS)

func WithKey(key any) VerifyOption {
	return func(jws_ *JWS) {
		jws_.key = key
	}
}

func (jws_ *JWS) Verify(opts ...VerifyOption) error {
	for _, opt := range opts {
		opt(jws_)
	}

	return nil
}
