package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	for {
		fmt.Println("1. Зашифровать")
		fmt.Println("2. Расшифровать")
		fmt.Println("0. Выход")
		var choise int
		fmt.Scan(&choise)
		switch choise {
		case 1:
			doEncrypt()
		case 2:
			doDecrypt()
		case 0:
			os.Exit(0)
		}
	}
}

func createHash(key string) string {
	hash := make([]byte, 32)
	copy(hash, key)
	return string(hash)
}

func encrypt(text, key string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(key)))

	if err != nil {
		return "", err
	}

	textBytes := []byte(text)
	ciphertext := make([]byte, aes.BlockSize+len(textBytes))
	iv := ciphertext[:aes.BlockSize]

	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], textBytes)

	return hex.EncodeToString(ciphertext), nil
}

func decrypt(encryptedText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		return "", err
	}

	ciphertext, _ := hex.DecodeString(encryptedText)
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("Шифрованное сообщение слишком короткое")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
func doEncrypt() {
	fmt.Println("Введите ключ")
	key, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	key = strings.TrimSpace(key)
	fmt.Println("Введите текст для шифрования")
	text, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	text = strings.TrimSpace(text)

	encrypted, _ := encrypt(text, key)
	fmt.Println("Зашифрованное сообщение: ", encrypted)

}

func doDecrypt() {
	fmt.Println("Введите ключ")
	key, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	key = strings.TrimSpace(key)
	fmt.Println("Введите текст для расшифровки")
	text, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	text = strings.TrimSpace(text)

	decrypted, _ := decrypt(text, key)
	fmt.Println("Расшифрованное сообщение: ", decrypted)

}
