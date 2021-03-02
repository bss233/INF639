package main

import (
	"fmt"
)

func test(Rounds int) {
	Message := "This is a test.." // Len 16 for testing
	fmt.Printf("Using Message : %v\n", Message)
	// Add round key
	Chunks := chunkMessage(Message)
	fmt.Printf("Chunked Message %v rounds\n", Chunks)

	fmt.Printf("Emulating AES after %v rounds\n", Rounds)

	CipherText := addKey(Chunks[0])

	fmt.Printf("After Key Addition : %v\n", CipherText)

	// loop
	for i := 0; i < Rounds; i++ {
		// SubBytes -- Working
		CipherText = subBytes(CipherText, SBOX)
		fmt.Printf("After subBytes : %v\n", CipherText)
		println()

		// ShiftRows -- Working
		CipherText = shiftRows(CipherText, false)
		fmt.Printf("After shiftRows : %v\n", CipherText)
		println()

		// MixColumns -- Working?
		CipherText = mixColumns(CipherText, 0)
		fmt.Printf("After mixColumns : %v\n", CipherText)
		println()

		// AddRoundKey
		CipherText = addKey(CipherText)
		fmt.Printf("After Key Addition : %v\n", CipherText)
		println()
	}
	// Final Round
	// subBytes
	CipherText = subBytes(CipherText, SBOX)
	fmt.Printf("After subBytes : %v\n", CipherText)
	println()
	// shiftRows
	CipherText = shiftRows(CipherText, false)
	fmt.Printf("After shiftRows : %v\n", CipherText)
	println()
	// addKey
	CipherText = addKey(CipherText)
	fmt.Printf("After Key Addition : %v\n", CipherText)
	println()
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

}
