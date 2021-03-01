package main

import "math/bits"

// AESChunk is the byte length accepted by AES
const AESChunk = 16

// RoundKeys is an array of Keys to uses in key scheduling
var RoundKeys = [6][16]uint8{
	{0x73, 0x75, 0x70, 0x65, 0x72, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x6b, 0x65, 0x79, 0x31, 0x1B},
	{0x71, 0x80, 0xba, 0x43, 0xcb, 0x15, 0xd3, 0x73, 0xa9, 0x19, 0x44, 0x6f, 0x91, 0x7e, 0x87, 0x29},
	{0xda, 0xf4, 0x7d, 0x8d, 0x3a, 0x32, 0x17, 0x2c, 0x4b, 0xbc, 0x43, 0x81, 0x6c, 0xb2, 0xa9, 0x6b},
	{0x84, 0x8d, 0x9d, 0xa1, 0xf3, 0x61, 0xb8, 0x71, 0xd2, 0x85, 0x7a, 0x40, 0xce, 0xb5, 0xe8, 0x12},
	{0x6b, 0x48, 0xea, 0x2d, 0x89, 0xcd, 0xcd, 0xa0, 0xbe, 0x6e, 0x99, 0x9b, 0x7a, 0xdf, 0x9b, 0xbb},
	{0x2c, 0x78, 0x48, 0x35, 0x34, 0xde, 0x10, 0x70, 0xa2, 0x52, 0x65, 0x90, 0x58, 0xb6, 0x38, 0x42}}

// MixColumnsMatrix is a 4x4 matrix used for the mix columns step of AES
var MixColumnsMatrix = [4][4]uint8{
	{0x02, 0x03, 0x01, 0x01},
	{0x01, 0x02, 0x03, 0x01},
	{0x01, 0x01, 0x02, 0x03},
	{0x03, 0x01, 0x01, 0x02}}

// InverseMixMaxtrix is a 4x4 matrix used for the decryption of AES
var InverseMixMaxtrix = [4][4]uint8{
	{0x0e, 0x0b, 0x0d, 0x09},
	{0x09, 0x0e, 0x0b, 0x0d},
	{0x0d, 0x09, 0x0e, 0x0b},
	{0x0b, 0x0d, 0x09, 0x0e}}

//SBOX is Rinjindael S-Box
var SBOX = [256]uint8{
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}

// RSBOX is the Reverse S-Box for decryption
var RSBOX = [256]uint8{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}

// addKey adds the round key to the cipherText
func addKey(CipherText []uint8) (AfterKey []uint8) {

	for Index, Hex := range CipherText {
		AfterKey = append(AfterKey, (Hex ^ RoundKeys[0][Index]))
	}

	return
}

// subBytes substitutes bytes in a string with their S-Box counterpart
// Returns string of bytes
func subBytes(CipherText []uint8, LT [256]uint8) (Result []uint8) {

	for _, Hex := range CipherText {
		Result = append(Result, LT[Hex])
	}

	return
}

// ShiftRows does the Shift Rows operation in AES encryption
// uses ShiftRowsWork as a helper function
func shiftRows(CipherText []uint8, Inverse bool) (ShiftedCipher []uint8) {

	MatrixForm := toShiftForm(CipherText)
	var ShiftedMatrix [][]uint8

	if Inverse {
		ShiftedMatrix = inverseShiftRowsWork(MatrixForm)
	} else {
		ShiftedMatrix = shiftRowsWork(MatrixForm)
	}

	ShiftedCipher = fromShiftForm(ShiftedMatrix)

	return
}

// shiftRowsWork shifts each row in the row matrix by it's index value
func shiftRowsWork(RowMatrix [][]uint8) (ShiftedMatrix [][]uint8) {

	var TempArr []uint8

	for RowIndex, Row := range RowMatrix {

		TempArr = make([]uint8, 0)

		for Iter := RowIndex; Iter < len(Row); Iter++ {
			TempArr = append(TempArr, Row[Iter])
		}

		for Iter := 0; Iter < RowIndex; Iter++ {
			TempArr = append(TempArr, Row[Iter])
		}
		ShiftedMatrix = append(ShiftedMatrix, TempArr)

	}
	return
}

func inverseShiftRowsWork(RowMatrix [][]uint8) (ShiftedMatrix [][]uint8) {

	var TempArr []uint8

	for RowIndex, Row := range RowMatrix {

		TempArr = make([]uint8, 0)
		if RowIndex == 0 || RowIndex == 2 {
			for Iter := RowIndex; Iter < len(Row); Iter++ {
				TempArr = append(TempArr, Row[Iter])
			}

			for Iter := 0; Iter < RowIndex; Iter++ {
				TempArr = append(TempArr, Row[Iter])
			}
			ShiftedMatrix = append(ShiftedMatrix, TempArr)
		} else {
			for Iter := len(Row) - RowIndex; Iter < len(Row); Iter++ {
				TempArr = append(TempArr, Row[Iter])
			}

			for Iter := 0; Iter < len(Row)-RowIndex; Iter++ {
				TempArr = append(TempArr, Row[Iter])
			}
			ShiftedMatrix = append(ShiftedMatrix, TempArr)
		}

	}
	return
}

// mixColumns performs the mix column operation of AES
func mixColumns(CipherText []uint8, MatrixSelect int) (MixedCipher []uint8) {
	MatrixForm := toMixForm(CipherText)

	MixedMatrix := mixColumnsWork(MatrixForm, MatrixSelect)

	MixedCipher = fromMixForm(MixedMatrix)
	return
}

func mixColumnsWork(Matrix [][]uint8, MatrixSelect int) (MixedMatrix [][]uint8) {
	var MixMatrix [4][4]uint8

	switch MatrixSelect {
	case 0:
		MixMatrix = MixColumnsMatrix

	case 1:
		MixMatrix = InverseMixMaxtrix
	default:
		MixMatrix = MixColumnsMatrix
	}

	for _, Column := range Matrix {
		MixedMatrix = append(MixedMatrix, mixMath(Column, MixMatrix))
	}
	return
}

// mixMath multiplies a column vector by a MixMatrix set by mixColumns
func mixMath(Column []uint8, MixMatrix [4][4]uint8) (RVector []uint8) {
	var TempArr []uint8
	var VectorVal uint8
	var NewVal uint8
	for _, Row := range MixMatrix {
		TempArr = make([]uint8, 0)
		for ColIndex, Val := range Row {
			VectorVal = Column[ColIndex]
			TempArr = append(TempArr, modMultiply(VectorVal, Val))
		}

		NewVal = TempArr[0]

		for i := 1; i < 4; i++ {
			NewVal = NewVal ^ TempArr[i]
		}

		RVector = append(RVector, NewVal)
	}

	return
}

// modMultiply does modulo multiplication between two uint8 values
func modMultiply(ValOne uint8, ValTwo uint8) (Result uint8) {
	AVal := uint(ValOne)
	BVal := uint(ValTwo)
	var Carry uint
	var PVal uint = 0
	for Counter := 0; Counter < 8; Counter++ {
		if bits.TrailingZeros(BVal) == 0 {
			PVal ^= AVal
		}
		Carry = AVal & 0x80
		AVal <<= 1
		if Carry != 0 {
			AVal ^= 0x001B
		}
		BVal >>= 1
	}
	Result = uint8(PVal)
	return
}
