package main

import (
	"bufio"
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
// as a matrix, into a single []uint8 representing a hex string
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

// fromMixForm takes a [][]uint8 representing a hex string
// as a matrix, into a single []uint8 representing a hex string
func fromMixForm(Matrix [][]uint8) (CipherText []uint8) {
	for _, Col := range Matrix {
		for _, Hex := range Col {
			CipherText = append(CipherText, Hex)
		}
	}
	return
}

// unchunkMessage
func unchunkMessage(Chunks [][]uint8) (FullMessage []uint8) {
	return
}

// hexToString
func hexToString(IntString []uint8) (HexString string) {
	return
}
