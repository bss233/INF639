package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

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

// getMessage gets plain text from stdio to encrypt
func getMessage() string {
	fmt.Println("Enter your message: ")
	var plainText string
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan() // use `for scanner.Scan()` to keep reading
	plainText = scanner.Text()
	return plainText
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
