package main

/* Need
Hex conversion
S-Box - Arrays?
Matrix Math
*/

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	// delete reflect before packaging
)

// AESChunk is the amount of bytes allowed for AES encryption
const AESChunk = 16

// tempKey is a string to use for key schedule testing
const tempKey = "73757065727365637265746b657931FF"

// MixColumnsMatrix is a 4x4 matrix used for the mix columns step of AES
var MixColumnsMatrix = [4][4]uint8{
	{02, 03, 01, 01},
	{01, 02, 03, 01},
	{01, 01, 02, 03},
	{03, 01, 01, 02}}

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

// Reverse S-Box for decryption
var rsbox = [256]uint8{
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

// main drives the demonstration of the AES tools
func main() {
	// Declare variables
	var message string
	var messageLen int
	//var result string
	// Get message input from user
	//message = getMessage() // Uncomment to get input from user
	message = "This is a test.." // Len 16 for testing
	//message = "This is a test!!!" // Len 17 for testing
	// Calculate message length, split into chunks of 16 characters, get any trailing characters
	messageLen = len(message)
	chunks := chunkMessage(message, messageLen)
	aesEncryption(chunks)
	// Encrypt chunk, append to result string
	//result += aes_encryption(messageChunk)

	/* -----------------------DEBUGGING--------------------------------/
	fmt.Printf( "Message Hex: %s\n", messageChunk )
	m := "01020304050607080910111213141516"
	m1 := ShiftRows(m)
	fmt.Printf("Original: %s\nShift Rows: %s\n", m, m1 )
	/ -----------------------END DEBUG--------------------------------*/
	//message := getMessage()
	// Return result string
	//return result
}

// chunkMessage takes a string and chunks it for AES
// the resulting chunks are 16 bytes in length
// chunks has an additional element at the last index that contains a string reduction of it's contents
func chunkMessage(message string, messageLen int) (chunks []string) {
	var minIndex int
	var maxIndex int
	var remainder int
	var messageChunk string
	lazy := ""
	chunks = make([]string, 0)
	numChunks := messageLen / AESChunk
	for index := 0; index <= numChunks; index++ {
		// Getindex of current chunk range
		minIndex = index * AESChunk
		maxIndex = minIndex + AESChunk

		// Check for index out of bounds, then chunk is the remainder, otherwise grab current chunk
		if maxIndex > messageLen {
			remainder = messageLen % AESChunk
			messageChunk = message[messageLen-remainder:]
		} else {
			messageChunk = message[minIndex:maxIndex]
		}
		fmt.Printf("Current chunk: %s\n", messageChunk) //DEBUG display chunk

		// Convert chunk to hex, overwrite plaintext chunk (good design choice?)
		messageChunk = encodeMessage(messageChunk)
		lazy += messageChunk
		chunks = append(chunks, messageChunk)
	}
	chunks = append(chunks, lazy)
	return
}

// SubBytes substitutes bytes in a string with their S-Box counterpart
// Returns string of bytes
func SubBytes(cipherText string) (result string) {
	//fmt.Printf("%s", cipherText[0:2])
	var selectedHex string
	for i := 0; i < len(cipherText); {
		selectedHex = cipherText[i : i+2]
		hexInt, _ := strconv.ParseInt(selectedHex, 16, 0)
		swap := SBOX[int(hexInt)]
		result += fmt.Sprintf("%02x", swap)
		i += 2

	}
	return

}

func buildShiftGroups(workingString string) (groups []string) {
	// No shift is [0:2], [8:10], [16:18], [24:26]
	// One shift is [1:4], [10:12], [18:20], [26:28]
	// Two shift is [3:6], [12:14], [20:22], [28:30]
	// Three shift is [5:8], [14:16], [22:24], [30:32]
	var noShift, oneShift, twoShift, threeShift string

	for i := 0; i < 32; {
		noShift += workingString[i : i+2]
		i += 8
	}
	groups = append(groups, noShift)

	for i := 2; i < 32; {
		oneShift += workingString[i : i+2]
		i += 8
	}
	groups = append(groups, oneShift)

	for i := 4; i < 32; {
		twoShift += workingString[i : i+2]
		i += 8
	}
	groups = append(groups, twoShift)

	for i := 6; i < 32; {
		threeShift += workingString[i : i+2]
		i += 8
	}
	groups = append(groups, threeShift)

	//fmt.Printf("Groups: %s\n", groups)
	return groups
}

// ShiftRows does the Shift Rows operation in AES encryption
// uses ShiftRowsWork as a helper function
func ShiftRows(roundCipher string) (result []string) {
	result = make([]string, 4)
	groups := buildShiftGroups(roundCipher)
	result[0] = groups[0]
	oneShift := ShiftRowsWork(groups[1], 1)
	result[1] = oneShift
	twoShift := ShiftRowsWork(groups[2], 2)
	result[2] = twoShift
	threeShift := ShiftRowsWork(groups[3], 3)
	result[3] = threeShift
	return result
}

// ShiftRowsWork reorders a hex string
func ShiftRowsWork(row string, shiftAmount int) (copyStr string) {
	copyStr = row
	for counter := 0; counter < shiftAmount; counter++ {
		copyStr = copyStr[2:] + copyStr[:2]
	}

	return
}

// getMessage gets plain text from stdio to encrypt
func getMessage() string {
	fmt.Println("Enter your message: ")
	var plainText string
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan() // use `for scanner.Scan()` to keep reading
	plainText = scanner.Text()
	return plainText
}

func encodeMessage(rawMessage string) (encodedMessage string) {
	byteMessage := []byte(rawMessage)
	encodedMessage = hex.EncodeToString(byteMessage)
	return
}

func maxtrixToString(matrix []string) (newString string) {
	for _, substring := range matrix {
		newString += substring
	}
	return
}

func addKey(cipherText string) (newString string) {
	var subKey, subString int64
	var err error
	for i := 0; i <= len(cipherText); {
		if i < 32 {
			subString, _ = strconv.ParseInt(cipherText[i:i+2], 16, 0)
			subKey, _ = strconv.ParseInt(tempKey[i:i+2], 16, 0)
		} else {
			subString, _ = strconv.ParseInt(cipherText[i:], 16, 0)
			subKey, _ = strconv.ParseInt(tempKey[i:], 16, 0)
		}

		if err == nil {
			xorVal := subString ^ subKey
			newString += fmt.Sprintf("%02x", xorVal)
			i += 2
		} else {
			break
		}
	}
	return
}

/* main aes encryption function that calls the other 4 steps
Returns ciphertext */
func aesEncryption(toEncypt []string) {
	cipherText := toEncypt[len(toEncypt)-1]
	// Add round key
	cipherText = addKey(cipherText)

	for i := 0; i < 10; i++ {
		// SubBytes -- Working
		cipherText = SubBytes(cipherText)
		// ShiftRows -- Working
		cipherMatrix := ShiftRows(cipherText)
		// MixColumns -- Working?
		cipherMatrix = mixColumns(cipherMatrix)
		cipherText = maxtrixToString(cipherMatrix)
		// AddRoundKey
		cipherText = addKey(cipherText)
	}

	// STRUCTURE - Initial round

	// Loop for 9 main rounds

	// Final round

	// Return cipherText
}

// buildColumn is used to arrange the given string into "AES Columns"
// AES Columns strings comprised of all hex pairs at a given index
func buildColumn(matrix []string, startIndex int) (newCol string) {
	for _, value := range matrix {
		newCol += value[startIndex : startIndex+2]
	}
	return newCol
}

func mixColumns(cipherMatrix []string) (resultMatrix []string) {
	mathMatrix := make([]string, 0)

	for i := 0; i <= 6; {
		mathMatrix = append(mathMatrix, buildColumn(cipherMatrix, i))
		i += 2
	}

	for _, column := range mathMatrix {
		//fmt.Printf("Col: %v, %v\n", col_index, column)
		intCol := buildBytes(column)
		mixedCol := mixColumnMath(intCol)
		fmt.Printf("Mixed Column: %v\n", mixedCol)
		resultMatrix = append(resultMatrix, toHexString(mixedCol))

	}

	return
}

// toHexString takes slice of ints and converts it to a single string
func toHexString(array []int64) (hexString string) {
	for _, value := range array {
		hex := fmt.Sprintf("%02x", value)
		hexString += hex
	}
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

// mixColumnMath performs galois matrix multiplicaton on a given vector
// It uses the AES Mix Columns Maxtrix as the matrix to multiply the vector with
func mixColumnMath(intVector []int64) (mixedCol []int64) {
	matrixSlices := make([][4]int64, 0)
	var tempArray [4]int64
	var tempVal int64
	for _, rowVector := range MixColumnsMatrix {

		for colIndex, vectorVal := range rowVector {

			currentVal := intVector[colIndex]

			if vectorVal != 1 {

				tempVal = currentVal * 2

				if vectorVal == 3 {
					tempVal = tempVal ^ currentVal
				}

				if tempVal > 255 { // Overflow
					xorVal := (tempVal ^ 27) - 256 // 1B in Hex
					tempVal = xorVal
				}

			} else {
				tempVal = currentVal
			}

			tempArray[colIndex] = tempVal
			if colIndex == 3 {
				matrixSlices = append(matrixSlices, tempArray)
			}

		}
	}

	// Actual Spaghetti
	mixedCol = mathHelper(matrixSlices)
	return
}

// buildBytes converts a string of length 8 to an array of integers
// It expects 8 characters which should represent 4 hex pairs
func buildBytes(hexString string) (hexArray []int64) {
	for i := 0; i < 8; {
		hexInt, _ := strconv.ParseInt(hexString[i:i+2], 16, 0)
		i += 2
		hexArray = append(hexArray, hexInt)
	}
	return
}
