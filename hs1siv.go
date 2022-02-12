// hs1siv.go - HS1-SIV
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package hs1siv implements the HS1-SIV Authenticated Cipher.
//
// While the specification defines multiple parameter sets, this implementation
// deliberately only supprorts the most conservative "hs1-siv-hi".
//
// This implementation is derived from the reference implementation by Ted
// Krovetz.
package hs1siv

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	// KeySize is the size of a key in bytes.
	KeySize = 32

	// NonceSize is the size of a nonce in bytes.
	NonceSize = 12

	// TagSize is the size of an authentication tag in bytes.
	TagSize = 32

	stateSize = chacha20KeySize + hashStateSize
)

var (
	// ErrInvalidKeySize is the error thrown via a panic when a key is an
	// invalid size.
	ErrInvalidKeySize = errors.New("hs1siv: invalid key size")

	// ErrInvalidNonceSize is the error thrown via a panic when a nonce is
	// an invalid size.
	ErrInvalidNonceSize = errors.New("hs1siv: invalid nonce size")

	// ErrOpen is the error returned when the message authentication fails
	// during an Open call.
	ErrOpen = errors.New("hs1siv: message authentication failed")

	settings = [chacha20NonceSize]byte{
		0, 0, hs1SIVLen, 0, chacha20Rounds, hs1HashRounds, hs1NHLen,
		0, 0, 0, 0,
	}
	zero [hs1SIVLen]byte
)

// AEAD is a HS1-SIV instance, implementing crypto/cipher.AEAD.
type AEAD struct {
	key []byte
}

// NonceSize returns the size of the nonce that must be passed to Seal and
// Open.
func (ae *AEAD) NonceSize() int {
	return NonceSize
}

// Overhead returns the maximum difference between the lengths of a plaintext
// and its ciphertext.
func (ae *AEAD) Overhead() int {
	return TagSize
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and should be unique for
// all time, for a given key.
//
// The plaintext and dst must overlap exactly or not at all. To reuse
// plaintext's storage for the encrypted output, use plaintext[:0] as dst.
func (ae *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic(ErrInvalidNonceSize)
	}

	var ctx aeadCtx
	ctx.setup(ae.key)
	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	ctx.encrypt(plaintext, additionalData, nonce, out)
	return ret
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// The ciphertext and dst must overlap exactly or not at all. To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (ae *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var err error
	var ok bool

	if len(nonce) != NonceSize {
		panic(ErrInvalidNonceSize)
	}

	var ctx aeadCtx
	ctx.setup(ae.key)
	ret, out := sliceForAppend(dst, len(ciphertext)-TagSize)
	ok = ctx.decrypt(ciphertext, additionalData, nonce, out)
	if !ok {
		// On decryption failures, purge the invalid plaintext.
		if len(out) > 0 {
			for i := range out {
				out[i] = 0
			}
			ret = nil
		}
		err = ErrOpen
	}
	return ret, err
}

// New returns a new keyed HS1-SIV instance.
func New(key []byte) *AEAD {
	if len(key) != KeySize {
		panic(ErrInvalidKeySize)
	}
	return &AEAD{key: append([]byte{}, key...)}
}

type aeadCtx struct {
	chachaKey [chacha20KeySize]byte
	hashCtx   hs1Ctx

	sivAccum  [hs1HashRounds]uint64
	sivLenBuf [16]byte
}

// XOR first n bytes of src into dst, then copy the next 32-n bytes.
func xorCopyChaChaKey(dst, src []byte) {
	const n = 24 // For 6 hash rounds.

	for i, v := range src[:n] {
		dst[i] ^= v
	}
	copy(dst[n:], src[n:])
}

func (ctx *aeadCtx) setup(userKey []byte) {
	// The paper allows a variable length key of up to 256 bits, the reference
	// implementation hard codes a 128 bit key.
	//
	// This implementation only supports a 256 bit key.
	var chachaNonce [chacha20NonceSize]byte
	copy(chachaNonce[:], settings[:])
	chachaNonce[0] = byte(len(userKey))
	var buf [stateSize]byte
	chacha20(userKey, chachaNonce[:], buf[:], buf[:], 0)

	off := chacha20KeySize
	copy(ctx.chachaKey[:], buf[:off])
	for i := range ctx.hashCtx.nhKey {
		ctx.hashCtx.nhKey[i] = binary.LittleEndian.Uint32(buf[off:])
		off += 4
	}
	for i := range ctx.hashCtx.polyKey {
		ctx.hashCtx.polyKey[i] = binary.LittleEndian.Uint64(buf[off:]) & m60
		off += 8
	}
	for i := range ctx.hashCtx.asuKey {
		ctx.hashCtx.asuKey[i] = binary.LittleEndian.Uint64(buf[off:])
		off += 8
	}
}

func (ctx *aeadCtx) sivSetup(aBytes, mBytes int) {
	// Init: set up lengths, accumulator.
	binary.LittleEndian.PutUint64(ctx.sivLenBuf[0:8], uint64(aBytes))
	binary.LittleEndian.PutUint64(ctx.sivLenBuf[8:16], uint64(mBytes))
	for i := range ctx.sivAccum {
		ctx.sivAccum[i] = 1
	}
}

func (ctx *aeadCtx) sivHashAD(a []byte) {
	aBytes := len(a)

	// Hash associated data.
	nhMultiple := aBytes & ^(hs1NHLen - 1)
	hashStep(&ctx.hashCtx, a[:nhMultiple], &ctx.sivAccum)
	if nhMultiple < aBytes {
		var buf [hs1NHLen]byte
		copy(buf[:], a[nhMultiple:])
		hashStep(&ctx.hashCtx, buf[:], &ctx.sivAccum)
	}
}

func (ctx *aeadCtx) sivGenerate(m, n, siv []byte) {
	mBytes := len(m)

	// Hash message data.
	var chachaKey [chacha20KeySize]byte
	nhMultiple := mBytes & ^(hs1NHLen - 1)
	hashStep(&ctx.hashCtx, m[:nhMultiple], &ctx.sivAccum)
	mBytes = mBytes - nhMultiple
	mBytesWithPadding := (mBytes + 15) & ^15
	if mBytesWithPadding == hs1NHLen {
		var buf [hs1NHLen]byte
		copy(buf[:], m[nhMultiple:])
		hashStep(&ctx.hashCtx, buf[:], &ctx.sivAccum)
		hashFinalize(&ctx.hashCtx, ctx.sivLenBuf[:], &ctx.sivAccum, chachaKey[:])
	} else {
		var buf [hs1NHLen]byte
		copy(buf[:], m[nhMultiple:])
		copy(buf[mBytesWithPadding:], ctx.sivLenBuf[:])
		hashFinalize(&ctx.hashCtx, buf[:mBytesWithPadding+16], &ctx.sivAccum, chachaKey[:])
	}

	// Derive the SIV.
	xorCopyChaChaKey(chachaKey[:], ctx.chachaKey[:])
	chacha20(chachaKey[:], n, zero[:], siv, 0)
}

func (ctx *aeadCtx) encrypt(m, a, n, c []byte) {
	mBytes := len(m)
	var accum [hs1HashRounds]uint64
	for i := range accum {
		accum[i] = 1
	}

	var siv [hs1SIVLen]byte
	ctx.sivSetup(len(a), len(m))
	ctx.sivHashAD(a)
	ctx.sivGenerate(m, n, siv[:])

	var chachaKey [chacha20KeySize]byte
	hashFinalize(&ctx.hashCtx, siv[:], &accum, chachaKey[:])
	xorCopyChaChaKey(chachaKey[:], ctx.chachaKey[:])
	chacha20(chachaKey[:], n, m, c, 1)
	copy(c[mBytes:], siv[:])
}

func (ctx *aeadCtx) decrypt(c, a, n, m []byte) bool {
	cBytes := len(c)
	if cBytes < hs1SIVLen {
		return false
	}
	mBytes := cBytes - hs1SIVLen

	var accum [hs1HashRounds]uint64
	for i := range accum {
		accum[i] = 1
	}

	var siv, maybeSIV [hs1SIVLen]byte
	var nonce [NonceSize]byte
	copy(siv[:], c[mBytes:])
	copy(nonce[:], n) // Work with a copy, `m` and `n` may alias.

	var chachaKey [chacha20KeySize]byte
	hashFinalize(&ctx.hashCtx, siv[:], &accum, chachaKey[:])
	xorCopyChaChaKey(chachaKey[:], ctx.chachaKey[:])
	ctx.sivSetup(len(a), len(m))
	ctx.sivHashAD(a) // Hash AD before decrption, `m` and `a` may alias.
	chacha20(chachaKey[:], nonce[:], c[:mBytes], m, 1)
	ctx.sivGenerate(m, nonce[:], maybeSIV[:])

	return subtle.ConstantTimeCompare(siv[:], maybeSIV[:]) == 1
}

// Shamelessly stolen from the Go runtime library.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
