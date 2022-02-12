// hs1.go - HS1 hash function
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package hs1siv

import "encoding/binary"

const (
	hs1NHLen      = 64 // Parameter b
	hs1HashRounds = 6  // Parameter t
	hs1SIVLen     = 32 // Parameter l

	m60 = (1 << 60) - 1
	m61 = (1 << 61) - 1

	hashStateSize = (hs1NHLen/4+4*(hs1HashRounds-1))*4 + hs1HashRounds*8 + hs1HashRounds*3*8
)

type hs1Ctx struct {
	nhKey   [hs1NHLen/4 + 4*(hs1HashRounds-1)]uint32
	polyKey [hs1HashRounds]uint64
	asuKey  [hs1HashRounds * 3]uint64
}

// Return 63 bits congruent to ak+b mod (2^61-1).  Assume 60-bit k,b 63-bit a.
func polyStep(a, b, k uint64) uint64 {
	// No uint128_t or equivalent.  Could use inline assembly here, but Go
	// can't/won't inline it, and the function call overhead will eclipse any
	// performance gain.
	m := uint64(uint32(a>>32))*uint64(uint32(k)) + uint64(uint32(k>>32))*uint64(uint32(a))
	h := uint64(uint32(a>>32)) * uint64(uint32(k>>32))
	l := uint64(uint32(a)) * uint64(uint32(k))
	return (l & m61) + (h << 3) + (l >> 61) + b + (m >> 29) + ((m << 32) & m61)
}

// Reduce a mod (2^61-1) in constant time.
func polyFinalize(a uint64) uint64 {
	a = (a & m61) + (a >> 61)
	mask := uint64(int64((m61-1)-a) >> 63)
	return a - (mask & m61)
}

func asuHash(x uint64, k []uint64) uint32 {
	_ = k[2] // Bounds check elimination.
	t := k[0] + k[1]*uint64(uint32(x)) + k[2]*uint64(uint32(x>>32))
	return uint32(t >> 32)
}

func hashStep(ctx *hs1Ctx, in []byte, accum *[hs1HashRounds]uint64) {
	// len(in) MUST be a multiple of hs1NHLen.
	inBytes := len(in)
	for inBytes > 0 {
		var nhRes [hs1HashRounds]uint64
		for i := 0; 4*i < hs1NHLen; i += 4 {
			_ = in[15] // Bounds check elimination.
			mp0 := binary.LittleEndian.Uint32(in[0:4])
			mp1 := binary.LittleEndian.Uint32(in[4:8])
			mp2 := binary.LittleEndian.Uint32(in[8:12])
			mp3 := binary.LittleEndian.Uint32(in[12:16])
			for j := 0; j < hs1HashRounds; j += 2 {
				kp := ctx.nhKey[i+j*4:]
				_ = kp[7] // Bounds check elimination.

				nhRes[j+0] += uint64(mp0+kp[0]) * uint64(mp2+kp[2])
				nhRes[j+1] += uint64(mp0+kp[4]) * uint64(mp2+kp[6])
				nhRes[j+0] += uint64(mp1+kp[1]) * uint64(mp3+kp[3])
				nhRes[j+1] += uint64(mp1+kp[5]) * uint64(mp3+kp[7])
			}
			in = in[16:]
		}
		for j := 0; j < hs1HashRounds; j += 2 {
			accum[j] = polyStep(accum[j], nhRes[j]&m60, ctx.polyKey[j])
			accum[j+1] = polyStep(accum[j+1], nhRes[j+1]&m60, ctx.polyKey[j+1])
		}

		inBytes -= hs1NHLen
	}
}

func hashFinalize(ctx *hs1Ctx, in []byte, accum *[hs1HashRounds]uint64, result []byte) {
	inBytes := len(in)
	if inBytes > 0 {
		var nhRes [hs1HashRounds]uint64
		for i := 0; 4*i < inBytes; i += 4 {
			_ = in[15] // Bounds check elimination.
			mp0 := binary.LittleEndian.Uint32(in[0:4])
			mp1 := binary.LittleEndian.Uint32(in[4:8])
			mp2 := binary.LittleEndian.Uint32(in[8:12])
			mp3 := binary.LittleEndian.Uint32(in[12:16])
			in = in[16:]
			for j := 0; j < hs1HashRounds; j += 2 {
				kp := ctx.nhKey[i+j*4:]
				_ = kp[7] // Bounds check elimination.

				nhRes[j+0] += uint64(mp0+kp[0]) * uint64(mp2+kp[2])
				nhRes[j+1] += uint64(mp0+kp[4]) * uint64(mp2+kp[6])
				nhRes[j+0] += uint64(mp1+kp[1]) * uint64(mp3+kp[3])
				nhRes[j+1] += uint64(mp1+kp[5]) * uint64(mp3+kp[7])
			}
		}
		for j := 0; j < hs1HashRounds; j += 2 {
			accum[j] = polyStep(accum[j], nhRes[j]&m60, ctx.polyKey[j])
			accum[j+1] = polyStep(accum[j+1], nhRes[j+1]&m60, ctx.polyKey[j+1])
		}
	}
	for j := 0; j < hs1HashRounds; j += 2 {
		s0 := asuHash(polyFinalize(accum[j]), ctx.asuKey[3*j:])
		s1 := asuHash(polyFinalize(accum[j+1]), ctx.asuKey[3*j+3:])
		binary.LittleEndian.PutUint32(result[j*4:], s0)
		binary.LittleEndian.PutUint32(result[j*4+4:], s1)
	}
}
