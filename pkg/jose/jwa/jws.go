package jwa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"sync"
)

// JWSAlgorithm
//
//   - ref. https://www.rfc-editor.org/rfc/rfc7518#section-3.1
//
// 3.1.  "alg" (Algorithm) Header Parameter Values for JWS
//
//	The table below is the set of "alg" (algorithm) Header Parameter
//	values defined by this specification for use with JWS, each of which
//	is explained in more detail in the following sections:
//
//	+--------------+-------------------------------+--------------------+
//	| "alg" Param  | Digital Signature or MAC      | Implementation     |
//	| Value        | Algorithm                     | Requirements       |
//	+--------------+-------------------------------+--------------------+
//	| HS256        | HMAC using SHA-256            | Required           |
//	| HS384        | HMAC using SHA-384            | Optional           |
//	| HS512        | HMAC using SHA-512            | Optional           |
//	| RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
//	|              | SHA-256                       |                    |
//	| RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
//	|              | SHA-384                       |                    |
//	| RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
//	|              | SHA-512                       |                    |
//	| ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
//	| ES384        | ECDSA using P-384 and SHA-384 | Optional           |
//	| ES512        | ECDSA using P-521 and SHA-512 | Optional           |
//	| PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
//	|              | MGF1 with SHA-256             |                    |
//	| PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
//	|              | MGF1 with SHA-384             |                    |
//	| PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
//	|              | MGF1 with SHA-512             |                    |
//	| none         | No digital signature or MAC   | Optional           |
//	|              | performed                     |                    |
//	+--------------+-------------------------------+--------------------+
//
//	The use of "+" in the Implementation Requirements column indicates
//	that the requirement strength is likely to be increased in a future
//	version of the specification.
//
//	See Appendix A.1 for a table cross-referencing the JWS digital
//	signature and MAC "alg" (algorithm) values defined in this
//	specification with the equivalent identifiers used by other standards
//	and software packages.
type JWSAlgorithm interface {
	Sign(key any, signingInput string) (signatureEncoded string, err error)
	Verify(key any, signingInput string, signatureEncoded string) (err error)
}

const (
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"
	RS256 = "RS256"
	RS384 = "RS384"
	RS512 = "RS512"
	ES256 = "ES256"
	ES384 = "ES384"
	ES512 = "ES512"
	PS256 = "PS256"
	PS384 = "PS384"
	PS512 = "PS512"
	None  = "none"
)

//nolint:revive,stylecheck
type (
	_HS256 string
	_HS384 string
	_HS512 string
	_RS256 string
	_RS384 string
	_RS512 string
	_ES256 string
	_ES384 string
	_ES512 string
	_PS256 string
	_PS384 string
	_PS512 string
	_None  string
)

const (
	JWSAlgorithmHS256 _HS256 = HS256
	JWSAlgorithmHS384 _HS384 = HS384
	JWSAlgorithmHS512 _HS512 = HS512
	JWSAlgorithmRS256 _RS256 = RS256
	JWSAlgorithmRS384 _RS384 = RS384
	JWSAlgorithmRS512 _RS512 = RS512
	JWSAlgorithmES256 _ES256 = ES256
	JWSAlgorithmES384 _ES384 = ES384
	JWSAlgorithmES512 _ES512 = ES512
	JWSAlgorithmPS256 _PS256 = PS256
	JWSAlgorithmPS384 _PS384 = PS384
	JWSAlgorithmPS512 _PS512 = PS512
	JWSAlgorithmNone  _None  = None
)

//nolint:gochecknoglobals
var (
	_JWSAlgorithm = map[string]JWSAlgorithm{
		HS256: JWSAlgorithmHS256,
		HS384: JWSAlgorithmHS384,
		HS512: JWSAlgorithmHS512,
		RS256: JWSAlgorithmRS256,
		RS384: JWSAlgorithmRS384,
		RS512: JWSAlgorithmRS512,
		ES256: JWSAlgorithmES256,
		ES384: JWSAlgorithmES384,
		ES512: JWSAlgorithmES512,
		PS256: JWSAlgorithmPS256,
		PS384: JWSAlgorithmPS384,
		PS512: JWSAlgorithmPS512,
		None:  JWSAlgorithmNone,
	}
	_JWSAlgorithmMu sync.Mutex
)

var (
	ErrInvalidKeyReceived          = errors.New(`jwa: invalid key received`)
	ErrFailedToVerifySignature     = errors.New(`jwa: failed to verify signature`)
	ErrAlgorithmNoneIsNotSupported = errors.New(`jwa: algorithm "none" is not supported`)
	ErrNotImplemented              = errors.New(`jwa: not implemented`)
)

func JWS(alg string) JWSAlgorithm { //nolint:cyclop,ireturn
	if a, ok := _JWSAlgorithm[alg]; ok {
		return a
	}

	return _JWSAlgorithmFunc{
		sign:   func(_ any, _ string) (_ string, _ error) { return "", ErrNotImplemented },
		verify: func(_ any, _, _ string) (_ error) { return ErrNotImplemented },
	}
}

type (
	sign   = func(key any, signingInput string) (signatureEncoded string, err error)
	verify = func(key any, signingInput string, signatureEncoded string) (err error)
)

type _JWSAlgorithmFunc struct {
	sign   sign
	verify verify
}

func (alg _JWSAlgorithmFunc) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	if alg.sign != nil {
		return alg.sign(key, signingInput)
	}
	return "", ErrNotImplemented
}

func (alg _JWSAlgorithmFunc) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if alg.verify != nil {
		return alg.verify(key, signingInput, signatureEncoded)
	}
	return ErrNotImplemented
}

func RegisterJWSAlgorithm(alg string, jwsAlgorithm JWSAlgorithm) {
	_JWSAlgorithmMu.Lock()
	defer _JWSAlgorithmMu.Unlock()
	_JWSAlgorithm[alg] = jwsAlgorithm
}

func RegisterJWSAlgorithmFunc(alg string, sign sign, verify verify) {
	_JWSAlgorithmMu.Lock()
	defer _JWSAlgorithmMu.Unlock()
	_JWSAlgorithm[alg] = _JWSAlgorithmFunc{
		sign:   sign,
		verify: verify,
	}
}

func DeleteJWSAlgorithm(alg string) {
	_JWSAlgorithmMu.Lock()
	defer _JWSAlgorithmMu.Unlock()
	delete(_JWSAlgorithm, alg)
}

//
// HS
//

// Sign for HS256.
func (a _HS256) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signHS(key, signingInput, sha256.New)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for HS256.
func (a _HS256) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyHS(key, signingInput, signatureEncoded, sha256.New); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

// Sign for HS384.
func (a _HS384) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signHS(key, signingInput, sha512.New384)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for HS384.
func (a _HS384) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyHS(key, signingInput, signatureEncoded, sha512.New384); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

// Sign for HS512.
func (a _HS512) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signHS(key, signingInput, sha512.New)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for HS512.
func (a _HS512) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyHS(key, signingInput, signatureEncoded, sha512.New); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

//
// RS
//

// Sign for RS256.
func (a _RS256) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signRS(key, signingInput, sha256.New, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for RS256.
func (a _RS256) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyRS(key, signingInput, signatureEncoded, sha256.New, crypto.SHA256); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

// Sign for RS384.
func (a _RS384) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signRS(key, signingInput, sha512.New384, crypto.SHA384)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for RS384.
func (a _RS384) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyRS(key, signingInput, signatureEncoded, sha512.New384, crypto.SHA384); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

// Sign for RS512.
func (a _RS512) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signRS(key, signingInput, sha512.New, crypto.SHA512)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for RS512.
func (a _RS512) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyRS(key, signingInput, signatureEncoded, sha512.New, crypto.SHA512); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

//
// ES
//

// Sign for ES256.
func (a _ES256) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signES(key, signingInput, crypto.SHA256, 32)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for ES256.
func (a _ES256) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyES(key, signingInput, signatureEncoded, crypto.SHA256, 32); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

// Sign for ES384.
func (a _ES384) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signES(key, signingInput, crypto.SHA384, 48)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for ES384.
func (a _ES384) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyES(key, signingInput, signatureEncoded, crypto.SHA384, 48); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

// Sign for ES512.
func (a _ES512) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signES(key, signingInput, crypto.SHA512, 66)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for ES512.
func (a _ES512) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyES(key, signingInput, signatureEncoded, crypto.SHA512, 66); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

//
// PS
//

// Sign for PS256.
func (a _PS256) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signPS(key, signingInput, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for PS256.
func (a _PS256) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyPS(key, signingInput, signatureEncoded, sha256.New, crypto.SHA256, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

// Sign for PS384.
func (a _PS384) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signPS(key, signingInput, crypto.SHA384)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for PS384.
func (a _PS384) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyPS(key, signingInput, signatureEncoded, sha512.New384, crypto.SHA384, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

// Sign for PS512.
func (a _PS512) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	signatureEncoded, err = signPS(key, signingInput, crypto.SHA512)
	if err != nil {
		return "", fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return signatureEncoded, nil
}

// Verify for PS512.
func (a _PS512) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	if err := verifyPS(key, signingInput, signatureEncoded, sha512.New, crypto.SHA512, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
		return fmt.Errorf("alg=%s key=%T: %w", a, key, err)
	}
	return nil
}

//
// none
//

// Sign for none.
func (a _None) Sign(key any, signingInput string) (signatureEncoded string, err error) {
	return "", fmt.Errorf("alg=%s key=%T: %w", a, key, ErrAlgorithmNoneIsNotSupported)
}

// Verify for none.
func (a _None) Verify(key any, signingInput string, signatureEncoded string) (err error) {
	return fmt.Errorf("alg=%s key=%T: %w", a, key, ErrAlgorithmNoneIsNotSupported)
}
