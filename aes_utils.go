package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
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
