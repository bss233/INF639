package main

import (
	"fmt"
)

func test(Rounds int) {
	Message := "This is a test.." // Len 16 for testing
	fmt.Printf("Using Message : %v \n", Message)
	// Add round key
	Chunks := chunkMessage(Message)
	//fmt.Printf("Original Chunk: %v \n", Chunks[0])

	//CipherText := mixColumns(Chunks[0], 0)
	//fmt.Printf("Mixed columns : %v \n", CipherText)

	//PlainText := mixColumns(CipherText, 1)
	//fmt.Printf("Inverse mix : %v \n", PlainText)

	fmt.Printf("BEGIN TEST\n==========\n")
	fmt.Printf("Emulating AES after %v rounds\n", Rounds)
	fmt.Printf("Original Chunk: %v \n", Chunks[0])
	
	// add key
	CipherText1 := addKey(Chunks[0])
	fmt.Printf("\n\nINITIAL ROUND\n=============\n")
	fmt.Printf("After Added Key: %v \n", CipherText1)

	CipherText5 := Chunks[0] //just initializing cipher 5 outside the loop to use
	CipherText4 := Chunks[0] //just initializing cipher 4 outside the loop to use
	CipherText3 := Chunks[0] //just initializing cipher 3 outside the loop to use
	CipherText2 := Chunks[0] //just initializing cipher 2 outside the loop to use
	// loop
	for i := 0; i < Rounds; i++ {
		fmt.Printf("\n\nMAIN ROUND %v \n==========\n", i)

		// SubBytes -- Working
		CipherText2 = subBytes(CipherText1, SBOX)
		fmt.Printf("After Sub Bytes: %v \n", CipherText2)

		// ShiftRows -- Working
		CipherText3 = shiftRows(CipherText2, false)
		fmt.Printf("After Shift Rows: %v \n", CipherText3)
		// MixColumns -- Working?

		CipherText4 = mixColumns(CipherText3, 0)
		fmt.Printf("After Mix Columns: %v \n", CipherText4)
		
		// AddRoundKey
		CipherText5 = addKey(CipherText4)
		fmt.Printf("After Add Key: %v \n", CipherText5)
	}
	// Final Round
	fmt.Printf("\n\nFINAL ROUND\n===========\n")
	
	// subBytes
	CipherText6 := subBytes(CipherText5, SBOX)
	fmt.Printf("After Sub Bytes: %v \n", CipherText6)

	// shiftRows
	CipherText7 := shiftRows(CipherText6, false)
	fmt.Printf("After Shift Rows: %v \n", CipherText7)

	// addKey
	CipherText8 := addKey(CipherText7)
	fmt.Printf("Cipher Text after AES : %v\n", CipherText8)

	///////////////////////////////////////////////////////////////////////////

	fmt.Printf("\n\nEmulating AES Decryption\n")

	PlainText8 := addKey(CipherText8)
	fmt.Printf("\n\nINITIAL ROUND\n=============\n")
	fmt.Printf("After Add Key %v -->\n", PlainText8)
	/*if PlainText8 == CipherText8 {
		fmt.Printf("PASSED\n")
	}*/

	/*
	PlainText7 := shiftRows(PlainText8, true)
	fmt.Printf("After Shift Rows: %v --> ", PlainText7)
	if PlainText7 == CipherText7 {
		fmt.Printf("PASSED\n")
	}*/

	/*
	// InvByte Sub
	PlainText6 := subBytes(PlainText7, RSBOX)
	fmt.Printf("After Sub Bytes: %v --> ", PlainText6)
	if PlainText6 == CipherText6 {
		fmt.Printf("PASSED\n")
	}*/

	PlainText4 := Chunks[0] //just initalizing plaintext 4 to use outside loop
	// loop
	for i := 0; i < Rounds; i++ {
		fmt.Printf("\n\nMAIN ROUND %v \n==========\n", i)

		PlainText7 := shiftRows(PlainText8, true)
		fmt.Printf("After Shift Rows: %v -->\n", PlainText7)
		/*if PlainText7 == CipherText7 {
			fmt.Printf("PASSED\n")
		}*/

		// InvByte Sub
		PlainText6 := subBytes(PlainText7, RSBOX)
		fmt.Printf("After Sub Bytes: %v -->\n", PlainText6)
		/*if PlainText6 == CipherText6 {
			fmt.Printf("PASSED\n")
		}*/

		// Key addition
		PlainText5 := addKey(PlainText6)
		fmt.Printf("After Add Key %v -->\n", PlainText5)
		/*if PlainText5 == CipherText5 {
			fmt.Printf("PASSED\n")
		}*/

		// Inv Mix
		PlainText4 = mixColumns(PlainText5, 1)
		fmt.Printf("After Mix Columns: %v -->\n", PlainText4)
		/*if PlainText4 == CipherText4 {
			fmt.Printf("PASSED\n")
		}*/
	}
	// endloop
	fmt.Printf("\n\nFINAL ROUND\n===========\n")

	// Inv Shift Rows
	PlainText3 := shiftRows(PlainText4, true)
	fmt.Printf("After Shift Rows: %v -->\n", PlainText3)
	/*if PlainText3 == CipherText3 {
		fmt.Printf("PASSED\n")
	}*/
	
	// InvByte Sub
	PlainText2 := subBytes(PlainText3, RSBOX)
	fmt.Printf("After Sub Bytes: %v -->\n", PlainText2)
	/*if PlainText2 == CipherText2 {
		fmt.Printf("PASSED\n")
	}*/

	// Key addition
	PlainText1 := addKey(PlainText2)
	fmt.Printf("Plain Text after AES : %v -->\n", PlainText1)
	/*if PlainText1 == Chunks[0] {
		fmt.Printf("PASSED\n")
	}*/
}
