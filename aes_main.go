package main

import "fyne.io/fyne/v2/app"

// main drives the demonstration of the AES tools
func main() {
	//initialize
	RoundKeys := keySchedule(14)
	app := app.New()
	window := app.NewWindow("AES Demo")
	window.SetContent(loadUI(RoundKeys))
	window.ShowAndRun()
	//getMessage
	//PlainText := getMessage()
	//fmt.Printf("Original Plaintext Message: %v\n", PlainText)
	//chunkMessage

	/*fmt.Printf("Testing with : %s\n", message)
	CipherArr := aesEncryptionDriver(message, RoundKeys)
	fmt.Println(hexToString(unchunkMessage(CipherArr)))
	PlainText := aesDecryptionDriver(CipherArr, RoundKeys)
	fmt.Println(PlainText)*/
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

func aesEncryptionDriver(Digest string, RoundKeys [][]uint8) (CipherArr [][]uint8) {
	Chunks := chunkMessage(Digest)
	var CipherChunk []uint8
	for _, chunk := range Chunks {
		//aesEncryption
		CipherChunk = aesEncryption(chunk, RoundKeys)
		CipherArr = append(CipherArr, CipherChunk)
	}
	return
}

func aesDecryptionDriver(Digest string, RoundKeys [][]uint8) string {
	var PlainChunk []uint8
	var PlainArr [][]uint8
	Chunks := chunkHexString(Digest)
	for _, chunk := range Chunks {
		//aesDecryption
		PlainChunk = aesDecryption(chunk, RoundKeys)
		PlainArr = append(PlainArr, PlainChunk)
	}
	FullPlainText := unchunkMessage(PlainArr)
	PlainTextDecrypt := hexToString(FullPlainText)
	PlainTextDecrypt = toPlainText(PlainTextDecrypt)
	return PlainTextDecrypt
}
