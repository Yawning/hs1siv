// hwaccel_amd64.go - Hardware acceleration hooks
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64,!gccgo,!noasm,go1.10

package hs1siv

//go:noescape
func cpuidAmd64(cpuidParams *uint32)

//go:noescape
func xgetbv0Amd64(xcrVec *uint32)

//go:noescape
func chachaXORKeyStreamAVX2(s *chachaState, in, out []byte)

//go:noescape
func hashStepAVX2(ctx *hs1Ctx, in []byte, accum *[hs1HashRounds]uint64)

func supportsAVX2BMI2() bool {
	// https://software.intel.com/en-us/articles/how-to-detect-new-instruction-support-in-the-4th-generation-intel-core-processor-family
	const (
		osXsaveBit = 1 << 27
		avx2Bit    = 1 << 5
		bmi2Bit    = 1 << 8
	)

	// Check to see if CPUID actually supports the leaf required.
	// CPUID.(EAX=0H, ECX=0H) >= 7
	regs := [4]uint32{0x00}
	cpuidAmd64(&regs[0])
	if regs[0] < 7 {
		return false
	}

	// Check to see if the OS knows how to save/restore XMM/YMM state.
	// CPUID.(EAX=01H, ECX=0H):ECX.OSXSAVE[bit 27]==1
	regs = [4]uint32{0x01}
	cpuidAmd64(&regs[0])
	if regs[2]&osXsaveBit == 0 {
		return false
	}
	xcrRegs := [2]uint32{}
	xgetbv0Amd64(&xcrRegs[0])
	if xcrRegs[0]&6 != 6 {
		return false
	}

	// Check for AVX2 and BMI2 support.
	// CPUID.(EAX=07H, ECX=0H):EBX.AVX2[bit 5]==1
	// CPUID.(EAX=07H, ECX=0H):EBX.BMI2[bit 8]==1
	//
	// WARNING: Intel Skylake errata SKL052 implies that certain steppings
	// of Skylake Pentium/Celeron will lie and claim BMI2 support.  Said
	// parts do not have AVX2 support so this check is fine, since we care
	// about both.
	regs = [4]uint32{0x07}
	cpuidAmd64(&regs[0])
	return regs[1]&avx2Bit != 0 && regs[1]&bmi2Bit != 0
}

var implAVX2BMI2 = &hwaccelImpl{
	name:                 "AVX2",
	chachaXORKeyStreamFn: chachaXORKeyStreamAVX2,
	hashStepFn:           hashStepAVX2,
}

func initHardwareAcceleration() {
	if supportsAVX2BMI2() {
		hardwareAccelImpl = implAVX2BMI2
		isHardwareAccelerated = true
	}
}
