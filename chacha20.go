// chacha20.go - ChaCha20 convenience helper
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package hs1siv

import (
	rtChacha "golang.org/x/crypto/chacha20"
)

const (
	chacha20KeySize   = rtChacha.KeySize
	chacha20NonceSize = rtChacha.NonceSize
	chacha20Rounds    = 20
)

func chacha20(key, nonce, in, out []byte, initialCounter uint32) {
	chacha, err := rtChacha.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic("hs1siv: failed to instantiate chacha20: " + err.Error())
	}
	chacha.SetCounter(initialCounter)
	chacha.XORKeyStream(out, in)
}
