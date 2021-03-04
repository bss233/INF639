package main

import (
	"fmt"
)

// main drives the demonstration of the AES tools
func main() {
	//initialize
	var CipherArr [][]uint8
	var CipherChunk []uint8
	var PlainArr [][]uint8
	var PlainChunk []uint8
	RoundKeys := keySchedule(14)

	//getMessage
	PlainText := getMessage()
	fmt.Printf("Original Plaintext Message: %v\n", PlainText)

	//chunkMessage
	Chunks := chunkMessage(PlainText)
	fmt.Printf("Original Chunks: %v\n", Chunks)

	for _, chunk := range Chunks {
		//aesEncryption
		CipherChunk = aesEncryption(chunk, RoundKeys)
		CipherArr = append(CipherArr, CipherChunk)
	}
	fmt.Printf("Encrypted Chunks: %v\n\n", CipherArr)

	for _, chunk := range CipherArr {
		//aesDecryption
		PlainChunk = aesDecryption(chunk, RoundKeys)
		PlainArr = append(PlainArr, PlainChunk)
	}
	fmt.Printf("Decrypted Chunks: %v\n", PlainArr)

	FullPlainText := unchunkMessage(PlainArr)
	PlainTextDecrypt := hexToString(FullPlainText)
	PlainTextDecrypt = toPlainText(PlainTextDecrypt)
	fmt.Printf("Decrypted Plaintext Message: %v\n", PlainTextDecrypt)
}

func aesDecryption(CipherText []uint8, RoundKeys [][]uint8) (PlainText []uint8) {
	// add key
	PlainText = addKey(CipherText, RoundKeys, 14)
	// loop
	for i := 13; i > 0; i-- {
		// Inv Shift Rows
		PlainText = shiftRows(PlainText, true)
		// InvByte Sub
		PlainText = subBytes(PlainText, RSBOX)
		// Key addition
		PlainText = addKey(PlainText, RoundKeys, i)
		// Inv Mix
		PlainText = mixColumns(PlainText, 1)
	}
	// endloop
	// Inv Shift Rows
	PlainText = shiftRows(PlainText, true)
	// InvByte Sub
	PlainText = subBytes(PlainText, RSBOX)
	// Key addition
	PlainText = addKey(PlainText, RoundKeys, 0)
	return
}

// aesEncryption function that calls the other 4 steps
// Returns ciphertext
func aesEncryption(PlainText []uint8, RoundKeys [][]uint8) (CipherText []uint8) {
	// Add round key
	CipherText = addKey(PlainText, RoundKeys, 0)
	// loop
	for i := 1; i < 14; i++ {
		// SubBytes -- Working
		CipherText = subBytes(CipherText, SBOX)
		// ShiftRows -- Working
		CipherText = shiftRows(CipherText, false)
		// MixColumns -- Working?
		CipherText = mixColumns(CipherText, 0)
		// AddRoundKey
		CipherText = addKey(CipherText, RoundKeys, i)
	}
	// Final Round
	// subBytes
	CipherText = subBytes(CipherText, SBOX)
	// shiftRows
	CipherText = shiftRows(CipherText, false)
	// addKey
	CipherText = addKey(CipherText, RoundKeys, 14)
	return
}
