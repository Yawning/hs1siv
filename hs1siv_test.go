// hs1siv_test.go - HS1-SIV tests
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package hs1siv

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var canAccelerate bool

func mustInitHardwareAcceleration() {
	initHardwareAcceleration()
	if !IsHardwareAccelerated() {
		panic("initHardwareAcceleration() failed")
	}
}

func TestKAT(t *testing.T) {
	forceDisableHardwareAcceleration()
	impl := "_" + hardwareAccelImpl.name
	t.Run("HS1-SIV_KAT"+impl, func(t *testing.T) { doTestKAT(t) })

	if !canAccelerate {
		t.Log("Hardware acceleration not supported on this host.")
		return
	}
	mustInitHardwareAcceleration()
	impl = "_" + hardwareAccelImpl.name
	t.Run("HS1-SIV_KAT"+impl, func(t *testing.T) { doTestKAT(t) })
}

func doTestKAT(t *testing.T) {
	require := require.New(t)

	// There are no official test vectors, so the "known good" values used
	// by this test were generated by combining `genkat.c` from the NORX
	// source package and `supercop-20171218/crypto_aead/hs1sivhiv2/ref`.

	var w, h [256]byte
	var k [32]byte
	var n [12]byte

	for i := range w {
		w[i] = byte(255 & (i*197 + 123))
	}
	for i := range h {
		h[i] = byte(255 & (i*193 + 123))
	}
	for i := range k {
		k[i] = byte(255 & (i*191 + 123))
	}
	for i := range n {
		n[i] = byte(255 & (i*181 + 123))
	}

	var katAcc []byte
	katOff := 0

	aead := New(k[:])
	require.Equal(NonceSize, aead.NonceSize(), "NonceSize()")
	require.Equal(TagSize, aead.Overhead(), "Overhead()")

	for i := range w {
		katAcc = aead.Seal(katAcc, n[:], w[:i], h[:i])
		c := katAcc[katOff:]
		require.Len(c, i+TagSize, "Seal(): len(c) %d", i)
		require.Equal(kaths1siv[katOff:katOff+len(c)], c, "Seal(): %d", i)

		m, err := aead.Open(nil, n[:], c, h[:i])
		require.NoError(err, "Open(): %d", i)
		require.Len(m, i, "Open(): len(m) %d", i)
		if len(m) != 0 {
			require.Equal(m, w[:i], "Open(): m %d", i)
		}
		katOff += len(c)

		// Test malformed ciphertext.
		badC := append([]byte{}, c...)
		badC[i] ^= 0x23
		m, err = aead.Open(nil, n[:], badC, h[:i])
		require.Error(err, "Open(Bad c): %d", i)
		require.Nil(m, "Open(Bad c): len(m) %d", i)

		// Test malformed AD.
		if i > 0 {
			badH := append([]byte{}, h[:i]...)
			badH[i-1] ^= 0x23
			m, err = aead.Open(nil, n[:], c, badH)
			require.Error(err, "Open(Bad h): %d", i)
			require.Nil(m, "Open(Bad h): len(m) %d", i)
		}
	}
	require.Equal(kaths1siv, katAcc, "Final concatenated cipher texts.")
}

func BenchmarkHS1SIV(b *testing.B) {
	forceDisableHardwareAcceleration()
	doBenchmarkHS1SIV(b)

	if !canAccelerate {
		b.Log("Hardware acceleration not supported on this host.")
		return
	}
	mustInitHardwareAcceleration()
	doBenchmarkHS1SIV(b)
}

func doBenchmarkHS1SIV(b *testing.B) {
	benchSizes := []int{8, 32, 64, 576, 1536, 4096, 1024768}
	impl := "_" + hardwareAccelImpl.name

	for _, sz := range benchSizes {
		bn := "HS1-SIV" + impl + "_"
		sn := fmt.Sprintf("_%d", sz)
		b.Run(bn+"Encrypt"+sn, func(b *testing.B) { doBenchmarkAEADEncrypt(b, sz) })
		b.Run(bn+"Decrypt"+sn, func(b *testing.B) { doBenchmarkAEADDecrypt(b, sz) })
	}
}

func doBenchmarkAEADEncrypt(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, NonceSize), make([]byte, KeySize)
	m, c := make([]byte, sz), make([]byte, 0, sz+TagSize)
	rand.Read(nonce)
	rand.Read(key)
	rand.Read(m)
	aead := New(key)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c = c[:0]

		c = aead.Seal(c, nonce, m, nil)
		if len(c) != sz+TagSize {
			b.Fatalf("Seal failed")
		}
	}
}

func doBenchmarkAEADDecrypt(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, NonceSize), make([]byte, KeySize)
	m, c, d := make([]byte, sz), make([]byte, 0, sz+TagSize), make([]byte, 0, sz)
	rand.Read(nonce)
	rand.Read(key)
	rand.Read(m)
	aead := New(key)

	c = aead.Seal(c, nonce, m, nil)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		d = d[:0]

		var err error
		d, err = aead.Open(d, nonce, c, nil)
		if err != nil {
			b.Fatalf("Open failed")
		}
	}
	b.StopTimer()

	if !bytes.Equal(m, d) {
		b.Fatalf("Open output mismatch")
	}
}

func init() {
	canAccelerate = IsHardwareAccelerated()
}
