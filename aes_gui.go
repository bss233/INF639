package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
)

func loadUI(RoundKeys [][]uint8) fyne.CanvasObject {
	// for storing date during demo
	var cipherText string
	var messageText string
	var decryptText string
	var hexText string
	var cipherArr [][]uint8

	// binding for wathching data
	boundMessage := binding.BindString(&messageText)
	boundHex := binding.BindString(&hexText)

	cipherView := widget.NewMultiLineEntry()
	decryptView := widget.NewMultiLineEntry()

	// for getting input
	cipherBox := widget.NewEntryWithData(boundHex)
	messageBox := widget.NewEntryWithData(boundMessage)

	messageBox.PlaceHolder = "Please enter the message you'd like to encrypt"
	cipherBox.PlaceHolder = "Please enter the message you'd like to decrypt"

	encrypt := widget.NewButton("Encrypt", func() {
		cipherArr = aesEncryptionDriver(messageText, RoundKeys)
		cipherText = (hexToString(unchunkMessage(cipherArr)))
		cipherView.SetText(cipherText)
		messageText = ""
		boundMessage.Reload()
	})
	decrypt := widget.NewButton("Decrypt", func() {
		tempHex, _ := boundHex.Get()
		decryptText = aesDecryptionDriver(tempHex, RoundKeys)
		hexText = ""
		decryptView.SetText(decryptText)
		boundHex.Reload()

	})

	UI := container.NewAdaptiveGrid(2,
		messageBox, cipherBox,
		cipherView, decryptView,
		encrypt, decrypt)
	return UI
}
