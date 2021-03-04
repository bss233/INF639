package main

// BaseKey is the default key
var BaseKey = [4][4]uint8{
	{0x00, 0x01, 0x02, 0x03},
	{0x04, 0x05, 0x06, 0x07},
	{0x08, 0x09, 0x0A, 0x0B},
	{0x0C, 0x0D, 0x0E, 0x0F}}

// RCon array for key scheduling, one row represents one RCon vector for a round
var RCon = [14][4]uint8{
	{0x01, 0x00, 0x00, 0x00},
	{0x02, 0x00, 0x00, 0x00},
	{0x04, 0x00, 0x00, 0x00},
	{0x08, 0x00, 0x00, 0x00},
	{0x10, 0x00, 0x00, 0x00},
	{0x20, 0x00, 0x00, 0x00},
	{0x40, 0x00, 0x00, 0x00},
	{0x80, 0x00, 0x00, 0x00},
	{0x1B, 0x00, 0x00, 0x00},
	{0x36, 0x00, 0x00, 0x00},
	{0x6C, 0x00, 0x00, 0x00},
	{0xD8, 0x00, 0x00, 0x00},
	{0xAB, 0x00, 0x00, 0x00},
	{0x4D, 0x00, 0x00, 0x00}}

// rotWord responsible for performing rotation on a single word vector
func rotWord(WordVector []uint8) (NewWord []uint8) {
	// first byte in the vector is moved to the last byte
	NewWord = WordVector[1:]
	NewWord = append(NewWord, WordVector[0])
	return
}

// Performs the main iterable operations for creating the key schedule
func keySchedule(TotalRounds int) (ResultKeys [][]uint8) {
	// initialize the RoundKeys with the BaseKey as the first round
	var RoundKeys = [][]uint8{BaseKey[0][:], BaseKey[1][:], BaseKey[2][:], BaseKey[3][:]}

	// iterate through total rounds (14 rounds, 4 cols per round for AES-256)
	for round := 0; round < TotalRounds; round++ {
		// loop from 4 to 8 because first 4 is BaseKey
		for index := 4; index < 8; index++ {
			// initialize the column number for RoundKeys and the WordVector
			column := index + 4*round
			WordVector := RoundKeys[column-1]

			// check if the column is multiple of 4
			if column%4 == 0 {
				// rotate the word vector and sub bytes
				WordVector = rotWord(WordVector)
				WordVector = subBytes(WordVector, SBOX)

				// XOR the vector with RCon
				WordVector = xorVector(WordVector, RCon[round][:])
			}

			// XOR the vector with the same number column in previous block
			WordVector = xorVector(WordVector, RoundKeys[column-4])

			// append the vector to RoundKeys
			RoundKeys = append(RoundKeys, WordVector)
		}
	}

	ResultKeys = formatKeySchedule(RoundKeys, TotalRounds)
	return
}

// XORs two hex strings represented as [4]uint8 that are the same length
func xorVector(VectorOne []uint8, VectorTwo []uint8) (Result []uint8) {

	for index := range VectorOne {
		XORVal := VectorOne[index] ^ VectorTwo[index]
		Result = append(Result, XORVal)
	}

	return
}

// Formats from a [72][4]uint8 into a [15][16]uint8 for key scheduler
func formatKeySchedule(Matrix [][]uint8, TotalRounds int) (Result [][]uint8) {
	Flat := fromMixForm(Matrix)

	for round := 0; round < TotalRounds+1; round++ {
		start := 16 * round
		end := start + 16

		Result = append(Result, [][]uint8{Flat[start:end]}...)
	}

	return
}
