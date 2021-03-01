package main

import (
	"fmt"
)

func test(Rounds int) {
	Message := "This is a test.." // Len 16 for testing
	fmt.Printf("Using Message : %v\n", Message)
	// Add round key
	Chunks := chunkMessage(Message)

	CipherText := mixColumns(Chunks[0], 0)
	fmt.Printf("Mixed columns : %v \n", CipherText)

	PlainText := mixColumns(CipherText, 1)
	fmt.Printf("Inverse mix : %v \n", PlainText)

	/*
		fmt.Printf("Emulating AES after %v rounds\n", Rounds)
		CipherText := addKey(Chunks[0])
		// loop
		for i := 0; i < Rounds; i++ {
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
		fmt.Printf("Cipher Text after AES : %v\n", CipherText)

		fmt.Printf("Emulating AES Decryption\n")

		PlainText := addKey(CipherText)

		PlainText = shiftRows(PlainText, true)
		// InvByte Sub
		PlainText = subBytes(PlainText, RSBOX)
		// loop
		for i := 0; i < Rounds; i++ {
			PlainText = shiftRows(PlainText, true)
			// InvByte Sub
			PlainText = subBytes(PlainText, RSBOX)
			// Inv Mix
			PlainText = mixColumns(PlainText, 1)
			// Key addition
			PlainText = addKey(PlainText)
		}
		// endloop
		// Inv Shift Rows
		PlainText = shiftRows(PlainText, true)
		// InvByte Sub
		PlainText = subBytes(PlainText, RSBOX)
		// Key addition
		PlainText = addKey(PlainText)

		fmt.Printf("Cipher Text after AES : %v\n", PlainText)
	*/

}
