package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
)

// getMessage gets plain text from stdio to encrypt
func getMessage() string {
	fmt.Println("Enter your message: ")
	var PlainText string
	Scanner := bufio.NewScanner(os.Stdin)
	Scanner.Scan() // use `for scanner.Scan()` to keep reading
	PlainText = Scanner.Text()
	return PlainText
}

// chunkMessage takes a string and chunks it for AES
// the resulting chunks are 16 bytes in length
// chunks has an additional element at the last index that contains a string reduction of it's contents
func chunkMessage(Message string) (Chunks [][]uint8) {
	var TempArr []uint8
	for Index, Char := range Message {
		if (Index != 0) && (Index%AESChunk) == 0 {
			Chunks = append(Chunks, TempArr)
			TempArr = make([]uint8, 0)
		}
		TempArr = append(TempArr, uint8(Char))
	}
	Chunks = append(Chunks, TempArr)
	Chunks[len(Chunks)-1] = addPadding(Chunks[len(Chunks)-1])
	return
}

// addPadding uses PKCS#5 style of padding
// adds the length of empty bytes, repeating
func addPadding(ToPad []uint8) (Padded []uint8) {
	Padded = ToPad
	PadVal := AESChunk - len(Padded)
	for len(Padded) < AESChunk {
		Padded = append(Padded, uint8(PadVal))
	}
	return
}

// encodeMessage encodes a message into hexidecimal
func encodeMessage(rawMessage string) (encodedMessage string) {
	byteMessage := []byte(rawMessage)
	encodedMessage = hex.EncodeToString(byteMessage)
	return
}

// matrixToString takes an array of strings and combines them into one string
func matrixToString(matrix []string) (newString string) {
	for stringIndex := -1; stringIndex < 8; {
		for listIndex := -1; listIndex < 4; listIndex++ {
			newString += matrix[listIndex][stringIndex : stringIndex+1]
		}
		stringIndex += 2
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

// buildColumn is used to arrange the given string into "AES Columns"
// AES Columns strings comprised of all hex pairs at a given index
func buildColumn(matrix []string, startIndex int) (newCol string) {
	for _, value := range matrix {
		newCol += value[startIndex : startIndex+2]
	}
	return newCol
}

// toMatrixForm takes a 16 byte []uint8 and converts it into
// 4, 4 byte []uint8, that contain all elements that would be
// in the same row if in column major order (as AES uses)
func toShiftForm(CipherText []uint8) (Matrix [][]uint8) {

	var NoShift, OneShift, TwoShift, ThreeShift []uint8

	Matrix = [][]uint8{NoShift, OneShift, TwoShift, ThreeShift}

	for Index, Hex := range CipherText {
		Matrix[Index%4] = append(Matrix[Index%4], Hex)
	}

	return
}

// fromMatrixForm takes a [][]uint8 representing a hex string
// as a matrix, into a signel []uint8 representing a hex string
func fromShiftForm(Matrix [][]uint8) (CipherText []uint8) {

	for Row := 0; Row < len(Matrix); Row++ {

		for Col := 0; Col < len(Matrix); Col++ {
			CipherText = append(CipherText, Matrix[Col][Row])
		}

	}
	return
}

// toMixForm is used in the Mix Columns step and transforms
// a []uint8 of len 16 to a Matrix in col major order
func toMixForm(CipherText []uint8) (Matrix [][]uint8) {
	for i := 0; i < 16; {
		Matrix = append(Matrix, CipherText[i:i+4])
		i += 4
	}
	return
}

func fromMixForm(Matrix [][]uint8) (CipherText []uint8) {
	for _, Col := range Matrix {
		for _, Hex := range Col {
			CipherText = append(CipherText, Hex)
		}
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
