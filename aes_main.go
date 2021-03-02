package main

import (
	"fmt"
)

// x^8 + x^4 + x^3 + x^1 + x^0 ---->>> 100011011

// AESChunk is the amount of bytes allowed for AES encryption

// main drives the demonstration of the AES tools
func main() {
	//initialize
	var CipherArr [][]uint8
	var CipherChunk []uint8
	var PlainArr [][]uint8
	var PlainChunk []uint8

	//getMessage
	PlainText := getMessage()
	fmt.Printf("Original Plaintext Message: %v\n", PlainText)

	//chunkMessage
	Chunks := chunkMessage(PlainText)
	fmt.Printf("Original Chunks: %v\n", Chunks)

	for _, chunk := range Chunks {
		//aesEncryption
		CipherChunk = aesEncryption(chunk)
		CipherArr = append(CipherArr, CipherChunk)
	}
	fmt.Printf("Encrypted Chunks: %v\n\n", CipherArr)

	for _, chunk := range CipherArr {
		//aesDecryption
		PlainChunk = aesDecryption(chunk)
		PlainArr = append(PlainArr, PlainChunk)
	}
	fmt.Printf("Decrypted Chunks: %v\n", PlainArr)

	FullPlainText := unchunkMessage(PlainArr)
	PlainTextDecrypt := hexToString(FullPlainText)
	PlainTextDecrypt = toPlainText(PlainTextDecrypt)
	fmt.Printf("Decrypted Plaintext Message: %v\n", PlainTextDecrypt)
}

func aesDecryption(CipherText []uint8) (PlainText []uint8) {
	// add key
	PlainText = addKey(CipherText)
	// loop
	for i := 0; i < 13; i++ {
		// Inv Shift Rows
		PlainText = shiftRows(PlainText, true)
		// InvByte Sub
		PlainText = subBytes(PlainText, RSBOX)
		// Key addition
		PlainText = addKey(PlainText)
		// Inv Mix
		PlainText = mixColumns(PlainText, 1)
	}
	// endloop
	// Inv Shift Rows
	PlainText = shiftRows(PlainText, true)
	// InvByte Sub
	PlainText = subBytes(PlainText, RSBOX)
	// Key addition
	PlainText = addKey(PlainText)
	return
}

// aesEncryption function that calls the other 4 steps
// Returns ciphertext
func aesEncryption(PlainText []uint8) (CipherText []uint8) {
	// Add round key
	CipherText = addKey(PlainText)
	// loop
	for i := 0; i < 13; i++ {
		// SubBytes -- Working
		CipherText = subBytes(CipherText, SBOX)
		// ShiftRows -- Working
		CipherText = shiftRows(CipherText, false)
		// MixColumns -- Working?
		CipherText = mixColumns(CipherText, 0)
		// AddRoundKey
		CipherText = addKey(CipherText)
	}
	// Final Round
	// subBytes
	CipherText = subBytes(CipherText, SBOX)
	// shiftRows
	CipherText = shiftRows(CipherText, false)
	// addKey
	CipherText = addKey(CipherText)
	return
}
