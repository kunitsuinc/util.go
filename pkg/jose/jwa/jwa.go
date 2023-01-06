package jwa

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"sync"
)

var (
	ErrInvalidKeyReceived      = errors.New(`jws: invalid key received`)
	ErrFailedToVerifySignature = errors.New(`jws: failed to verify signature`)
)

// Algorithm
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
type Algorithm = string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	None  Algorithm = "none"
)

type JWSAlgorithm interface {
	Sign(key any, signingInput string) (signature string, err error)
	Verify(key any, signingInput string, signature string) (err error)
}

//nolint:gochecknoglobals
var (
	jwsAlgorithm = map[string]JWSAlgorithm{
		HS256: _HS256{},
		HS384: _HS384{},
		HS512: _HS512{},
	}
	jwsAlgorithmMu sync.Mutex
)

func Register(alg string, j JWSAlgorithm) {
	jwsAlgorithmMu.Lock()
	defer jwsAlgorithmMu.Unlock()
	jwsAlgorithm[alg] = j
}

//nolint:revive,stylecheck
type (
	_HS256 struct{}
	_HS384 struct{}
	_HS512 struct{}
)

func (_HS256) Sign(key any, signingInput string) (signature string, err error) {
	return signHS(key, signingInput, sha256.New)
}

func (_HS256) Verify(key any, signingInput string, signature string) (err error) {
	return verifyHS(key, signingInput, signature, sha256.New)
}

func (_HS384) Sign(key any, signingInput string) (signature string, err error) {
	return signHS(key, signingInput, sha512.New384)
}

func (_HS384) Verify(key any, signingInput string, signature string) (err error) {
	return verifyHS(key, signingInput, signature, sha512.New384)
}

func (_HS512) Sign(key any, signingInput string) (signature string, err error) {
	return signHS(key, signingInput, sha512.New)
}

func (_HS512) Verify(key any, signingInput string, signature string) (err error) {
	return verifyHS(key, signingInput, signature, sha512.New)
}
