package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	PasswdLength = 16
)

func Encrypt(plantText, key []byte) ([]byte, error) {
	pkey := PaddingLeft(key, '0', PasswdLength)
	block, err := aes.NewCipher(pkey) //选择加密算法
	if err != nil {
		return nil, err
	}
	plantText = PKCS7Padding(plantText, block.BlockSize())
	blockModel := cipher.NewCBCEncrypter(block, pkey)
	ciphertext := make([]byte, len(plantText))
	blockModel.CryptBlocks(ciphertext, plantText)
	return ciphertext, nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func DecryptHexText(hexText string, key []byte) ([]byte, error) {
	bytes, err := hex.DecodeString(hexText)
	if err != nil {
		return nil, err
	}
	return Decrypt(bytes, key)
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext is empty")
	}
	pkey := PaddingLeft(key, '0', PasswdLength)
	block, err := aes.NewCipher(pkey) //选择加密算法
	if err != nil {
		return nil, err
	}
	blockModel := cipher.NewCBCDecrypter(block, pkey)
	plantText := make([]byte, len(ciphertext))
	blockModel.CryptBlocks(plantText, []byte(ciphertext))
	plantText, err = PKCS7UnPadding(plantText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return plantText, nil
}

func PKCS7UnPadding(plantText []byte, blockSize int) ([]byte, error) {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	if unpadding < 0 || unpadding > length {
		return nil, errors.New("ciphertext's format is wrong")
	}
	return plantText[:(length - unpadding)], nil
}

func PaddingLeft(ori []byte, pad byte, length int) []byte {
	if len(ori) >= length {
		return ori[:length]
	}
	pads := bytes.Repeat([]byte{pad}, length-len(ori))
	return append(pads, ori...)
}

func WipeBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func InputPasswdForEncrypt() ([]byte, error) {

	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, oldState)

	fmt.Printf("Enter new password:")
	var pwd, rePwd []byte
	pwd, err = terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	fmt.Printf("\nPlease re-enter this password:")
	rePwd, err = terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pwd, rePwd) {
		return nil, errors.New("\nPassword not equal")
	}
	fmt.Printf("\nDone,please keep your password carefully!\n")
	WipeBytes(rePwd)
	// TODO Check pwd's security
	return pwd, nil
}

func InputPasswdForDecrypt() ([]byte, error) {
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, oldState)

	fmt.Printf("Enter password:")
	pwd, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("read password from terminal err:%v", err))
	}
	fmt.Println("")
	return pwd, nil
}
