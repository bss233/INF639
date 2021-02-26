package main

import (
	"fmt"
)

func test() {
	Message := "This is a test.." // Len 16 for testing
	//Message := "This is a test!!!" // Len 17 for testing
	fmt.Printf("Using message: %s \n", Message)

	//fromUser := getMessage()

	Chunks := chunkMessage(Message)
	fmt.Printf("Chunks: %v\n", Chunks)
	println()

	WorkingChunk := Chunks[0]
	WorkingChunk = addKey(WorkingChunk)
	fmt.Printf("After Key Addition: %v\n", WorkingChunk)
	println()

	WorkingChunk = subBytes(WorkingChunk, SBOX)
	fmt.Printf("After subBytes: %v\n\n", WorkingChunk)

	/* Test that reverse sub is working
	InverseSub := subBytes(WorkingChunk, RSBOX)
	fmt.Printf("Inverse Sub: %v\n", InverseSub)
	*/

	WorkingChunk = shiftRows(WorkingChunk)
	fmt.Printf("After shiftRows: %v\n\n", WorkingChunk)
}
