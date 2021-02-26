package main

import (
	"fmt"
)

func test() {
	//message := "aaaaaaaaaaaaaaaa" // Len 15 for testing
	message := "This is a test!!!" // Len 16 for testing
	fmt.Printf("Testing with message: %v\n", message)
	chunks := chunkMessage(message)
	fmt.Printf("Chunks: \n%v", chunks)
	encodedMessage := encodeMessage(message)
	//fmt.Printf("Encoded Message: %v\n", encodedMessage)

	///////////////////////////////////////////////////////

	// Test that we can add the key twice and get the same value
	addKeyOne := addKey(encodedMessage)
	fmt.Printf("Message after key addition: %v\n", addKeyOne)
	fmt.Println()
	//addKeyTwo := addKey(addKeyOne)
	//fmt.Printf("Message after second key addition: %v\n", addKeyTwo)
	// bool check
	//fmt.Printf("Undo xor pass: %v\n\n", encodedMessage == addKeyTwo)

	///////////////////////////////////////////////////////////

	// Test that we can sub bytes then inverse and get the original string
	subBytesEncrypt := SubBytes(addKeyOne)
	fmt.Printf("Message after Sub Bytes: %v\n", subBytesEncrypt)
	fmt.Println()

	//subBytesDecrypt := InvSubBytes(subBytesEncrypt)
	//fmt.Printf("Message after Inv Sub Bytes: %v\n", subBytesDecrypt)
	// bool check
	//fmt.Printf("Undo Shift pass: %v\n\n", addKeyOne == subBytesDecrypt)

	/////////////////////////////////////////////////////////

	// Test that we can shift rows then inverse shift
	shiftRowsEncrypt := ShiftRows(subBytesEncrypt)
	fmt.Printf("Message after Shift Rows: %v\n", shiftRowsEncrypt)
	fmt.Println()

	backToStringEncrypt := matrixToString(shiftRowsEncrypt)
	fmt.Printf("From matrix to string: %v\n", backToStringEncrypt)
	fmt.Println()

	//shiftRowsDecrypt := invShiftRows(backToStringEncrypt)
	//fmt.Printf("Message after Inv Shift Rows: %v\n", shiftRowsDecrypt)

	//backToStringDecrypt := matrixToString(shiftRowsDecrypt)
	//fmt.Printf("From matrix to string: %v\n", backToStringDecrypt)
	// bool check
	//fmt.Printf("Compare after inv shift: %v\n\n", subBytesEncrypt == backToStringDecrypt)

	//////////////////////////////////////////////////////////////
	fmt.Println("Mix Columns")

	// Test mix columns
	mixColEncrypt := mixColumns(shiftRowsEncrypt, -1)
	//fmt.Printf("After Encrypt Mix: %v\n", mixColEncrypt)
	colEncryptString := matrixToString(mixColEncrypt)
	fmt.Printf("From matrix to string: %v\n", colEncryptString)

	mixColDecrypt := mixColumns(mixColEncrypt, 0)
	fmt.Printf("After Decrypt Mix: %v\n", mixColDecrypt)
	colDecryptString := matrixToString(mixColDecrypt)
	fmt.Printf("From matrix to string: %v\n", colDecryptString)

}
