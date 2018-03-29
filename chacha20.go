// chacha20.go - RFC 7539 ChaCha20
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package hs1siv

import (
	"encoding/binary"
	"math/bits"
)

const (
	sigma0 = 0x61707865
	sigma1 = 0x3320646e
	sigma2 = 0x79622d32
	sigma3 = 0x6b206574

	chachaKeySize   = 32
	chachaNonceSize = 12
	chachaStateSize = 16
	chachaBlockSize = 64
	chachaRounds    = 20 // Parameter r
)

type chachaState [chachaStateSize]uint32

func chacha20(key, nonce, in, out []byte, initialCounter uint32) {
	if len(key) != chachaKeySize {
		panic("hs1siv: invalid chacha key size")
	}
	if len(nonce) != chachaNonceSize {
		panic("hs1siv: invalid chacha nonce size")
	}
	if len(in) == 0 {
		return
	}

	if len(out) < len(in) {
		in = in[:len(out)]
	}

	_, _ = key[31], nonce[11] // Bounds check elimination.
	s := &chachaState{
		sigma0, sigma1, sigma2, sigma3,
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
		initialCounter,
		binary.LittleEndian.Uint32(nonce[0:4]),
		binary.LittleEndian.Uint32(nonce[4:8]),
		binary.LittleEndian.Uint32(nonce[8:12]),
	}

	chachaXORKeyStream(s, in, out)

	// Purge the state off the stack.
	burnUint32s(s[:])
}

func chachaXORKeyStreamRef(s *chachaState, in, out []byte) {
	// Process full blocks.
	off, inLen := 0, len(in)
	if fullBlocks := inLen / chachaBlockSize; fullBlocks > 0 {
		chachaBlocksRef(s, in, out, fullBlocks)
		off += fullBlocks * chachaBlockSize
		inLen -= fullBlocks * chachaBlockSize
	}

	// Process the partial block, if any.
	if inLen > 0 {
		var partial [chachaBlockSize]byte
		copy(partial[:], in[off:])
		chachaBlocksRef(s, partial[:], partial[:], 1)
		copy(out[off:], partial[:])
	}
}

func chachaBlocksRef(s *chachaState, in, out []byte, nrBlocks int) {
	s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15 := s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15]

	for nrBlocks > 0 {
		x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15

		for i := chachaRounds; i > 0; i -= 2 {
			x0 += x4
			x12 ^= x0
			x12 = bits.RotateLeft32(x12, 16)
			x8 += x12
			x4 ^= x8
			x4 = bits.RotateLeft32(x4, 12)
			x0 += x4
			x12 ^= x0
			x12 = bits.RotateLeft32(x12, 8)
			x8 += x12
			x4 ^= x8
			x4 = bits.RotateLeft32(x4, 7)

			x1 += x5
			x13 ^= x1
			x13 = bits.RotateLeft32(x13, 16)
			x9 += x13
			x5 ^= x9
			x5 = bits.RotateLeft32(x5, 12)
			x1 += x5
			x13 ^= x1
			x13 = bits.RotateLeft32(x13, 8)
			x9 += x13
			x5 ^= x9
			x5 = bits.RotateLeft32(x5, 7)

			x2 += x6
			x14 ^= x2
			x14 = bits.RotateLeft32(x14, 16)
			x10 += x14
			x6 ^= x10
			x6 = bits.RotateLeft32(x6, 12)
			x2 += x6
			x14 ^= x2
			x14 = bits.RotateLeft32(x14, 8)
			x10 += x14
			x6 ^= x10
			x6 = bits.RotateLeft32(x6, 7)

			x3 += x7
			x15 ^= x3
			x15 = bits.RotateLeft32(x15, 16)
			x11 += x15
			x7 ^= x11
			x7 = bits.RotateLeft32(x7, 12)
			x3 += x7
			x15 ^= x3
			x15 = bits.RotateLeft32(x15, 8)
			x11 += x15
			x7 ^= x11
			x7 = bits.RotateLeft32(x7, 7)

			x0 += x5
			x15 ^= x0
			x15 = bits.RotateLeft32(x15, 16)
			x10 += x15
			x5 ^= x10
			x5 = bits.RotateLeft32(x5, 12)
			x0 += x5
			x15 ^= x0
			x15 = bits.RotateLeft32(x15, 8)
			x10 += x15
			x5 ^= x10
			x5 = bits.RotateLeft32(x5, 7)

			x1 += x6
			x12 ^= x1
			x12 = bits.RotateLeft32(x12, 16)
			x11 += x12
			x6 ^= x11
			x6 = bits.RotateLeft32(x6, 12)
			x1 += x6
			x12 ^= x1
			x12 = bits.RotateLeft32(x12, 8)
			x11 += x12
			x6 ^= x11
			x6 = bits.RotateLeft32(x6, 7)

			x2 += x7
			x13 ^= x2
			x13 = bits.RotateLeft32(x13, 16)
			x8 += x13
			x7 ^= x8
			x7 = bits.RotateLeft32(x7, 12)
			x2 += x7
			x13 ^= x2
			x13 = bits.RotateLeft32(x13, 8)
			x8 += x13
			x7 ^= x8
			x7 = bits.RotateLeft32(x7, 7)

			x3 += x4
			x14 ^= x3
			x14 = bits.RotateLeft32(x14, 16)
			x9 += x14
			x4 ^= x9
			x4 = bits.RotateLeft32(x4, 12)
			x3 += x4
			x14 ^= x3
			x14 = bits.RotateLeft32(x14, 8)
			x9 += x14
			x4 ^= x9
			x4 = bits.RotateLeft32(x4, 7)
		}

		_, _ = in[chachaBlockSize-1], out[chachaBlockSize-1] // Bounds check elimination.
		binary.LittleEndian.PutUint32(out[0:4], binary.LittleEndian.Uint32(in[0:4])^(x0+s0))
		binary.LittleEndian.PutUint32(out[4:8], binary.LittleEndian.Uint32(in[4:8])^(x1+s1))
		binary.LittleEndian.PutUint32(out[8:12], binary.LittleEndian.Uint32(in[8:12])^(x2+s2))
		binary.LittleEndian.PutUint32(out[12:16], binary.LittleEndian.Uint32(in[12:16])^(x3+s3))
		binary.LittleEndian.PutUint32(out[16:20], binary.LittleEndian.Uint32(in[16:20])^(x4+s4))
		binary.LittleEndian.PutUint32(out[20:24], binary.LittleEndian.Uint32(in[20:24])^(x5+s5))
		binary.LittleEndian.PutUint32(out[24:28], binary.LittleEndian.Uint32(in[24:28])^(x6+s6))
		binary.LittleEndian.PutUint32(out[28:32], binary.LittleEndian.Uint32(in[28:32])^(x7+s7))
		binary.LittleEndian.PutUint32(out[32:36], binary.LittleEndian.Uint32(in[32:36])^(x8+s8))
		binary.LittleEndian.PutUint32(out[36:40], binary.LittleEndian.Uint32(in[36:40])^(x9+s9))
		binary.LittleEndian.PutUint32(out[40:44], binary.LittleEndian.Uint32(in[40:44])^(x10+s10))
		binary.LittleEndian.PutUint32(out[44:48], binary.LittleEndian.Uint32(in[44:48])^(x11+s11))
		binary.LittleEndian.PutUint32(out[48:52], binary.LittleEndian.Uint32(in[48:52])^(x12+s12))
		binary.LittleEndian.PutUint32(out[52:56], binary.LittleEndian.Uint32(in[52:56])^(x13+s13))
		binary.LittleEndian.PutUint32(out[56:60], binary.LittleEndian.Uint32(in[56:60])^(x14+s14))
		binary.LittleEndian.PutUint32(out[60:64], binary.LittleEndian.Uint32(in[60:64])^(x15+s15))

		in, out = in[chachaBlockSize:], out[chachaBlockSize:]
		s12, nrBlocks = s12+1, nrBlocks-1
	}

	s[12] = s12
}
