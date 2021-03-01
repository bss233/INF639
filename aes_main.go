package main

// x^8 + x^4 + x^3 + x^1 + x^0 ---->>> 100011011

// AESChunk is the amount of bytes allowed for AES encryption

// main drives the demonstration of the AES tools
func main() {
	test(1)
	// Get message
	// Chunk message
	// AES over chunks
	//var ChunkedCipher [][]uint8
	/*
		// Encrypt Chunks
		for _, Chunk := range Chunks {
			ChunkedCipher = append(ChunkedCipher, aesEncryption(Chunk))
		}
		fmt.Printf("Chunked AES Cipher: %v\n", ChunkedCipher)

		// Decrypt Chunks
		var DecryptedChunks [][]uint8
		for _, Chunk := range ChunkedCipher {
			DecryptedChunks = append(DecryptedChunks, aesDecryption(Chunk))
		}
		fmt.Printf("Decrypted Cipher: %v\n", DecryptedChunks)
	*/
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
