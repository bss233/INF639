package main

// x^8 + x^4 + x^3 + x^1 + x^0 ---->>> 100011011

// AESChunk is the amount of bytes allowed for AES encryption

// main drives the demonstration of the AES tools
func main() {
	test()
	// Get message
	// Chunk message
	// AES over chunks
}

func aesDecryption(CipherText []uint8) (PlainText []uint8) {
	// add key
	// loop
	// Inv Mix
	// Key addition
	// InvByte Sub
	// Inv Shift Rows
	// endloop
	// Inv Shift
	// InvByte sub
	// Key addition
	return
}

// aesEncryption function that calls the other 4 steps
// Returns ciphertext
func aesEncryption(PlainText []uint8) (CipherText []uint8) {
	// Add round key
	// loop
	// SubBytes -- Working
	// ShiftRows -- Working
	// MixColumns -- Working?
	// AddRoundKey
	// Final Round
	// subBytes
	// shiftRows
	// addKey
	return
}

// mathHelper xors all values in a vector and returns the result
func mathHelper(vector [][4]int64) (resultVector []int64) {
	var val int64
	for _, vectorSet := range vector {
		val = vectorSet[0]
		for i := 1; i < 4; i++ {
			val = val ^ vectorSet[i]
		}
		resultVector = append(resultVector, val)
	}
	return
}

/*
func mixColMath(intVector []int64, matrixSelect int) (mixedCol []int64) {
	matrixSlices := make([][4]int64, 0)
	var tempArray [4]int64
	var tempVal int64
	var mixMatrix [4][4]uint8
	switch matrixSelect {
	case 0:
		mixMatrix = MixColumnsMatrix
	case 1:
		mixMatrix = InverseMixMaxtrix
	}
	for _, rowVector := range mixMatrix {

		for colIndex, vectorVal := range rowVector {
			currentVal := intVector[colIndex]
			tempVal = currentVal
			switch vectorVal {
			case 1:
				tempVal = currentVal

			case 2:
				tempVal = (tempVal * 2)

			case 3:
				tempVal = (tempVal * 3)

			case 9:
				tempVal = (tempVal * 9)

			case 11:
				tempVal = (tempVal * 11)

			case 13:
				tempVal = (tempVal * 13)

			case 14:
				tempVal = (tempVal * 14)
			}

			tempArray[colIndex] = tempVal
			if colIndex == 3 {
				matrixSlices = append(matrixSlices, tempArray)
			}

		}
	}

	mixedCol = mathHelper(matrixSlices)
	return
}
*/

/*
func invShiftRows(roundCipher string) (result []string) {
	result = make([]string, 4)
	groups := buildShiftGroups(roundCipher)
	result[0] = groups[0]
	oneShift := ShiftRowsWork(groups[1], 3)
	result[1] = oneShift
	twoShift := ShiftRowsWork(groups[2], 2)
	result[2] = twoShift
	threeShift := ShiftRowsWork(groups[3], 1)
	result[3] = threeShift
	return result
}
*/
