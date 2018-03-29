// hwaccel.go - Hardware acceleration hooks
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to the software, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package hs1siv

const implReference = "Reference"

var (
	isHardwareAccelerated = false
	hardwareAccelImpl     = implReference
)

func forceDisableHardwareAcceleration() {
	isHardwareAccelerated = false
	hardwareAccelImpl = implReference
}

// IsHardwareAccelerated returns true iff the HS1-SIV implementation will use
// hardware acceleration (eg: AVX2).
func IsHardwareAccelerated() bool {
	return isHardwareAccelerated
}

func init() {
	initHardwareAcceleration()
}
