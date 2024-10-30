package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// сохранение закрытого ключа
func savePEMKey(filename string, key *rsa.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	return pem.Encode(file, block)
}

func savePublicPEMKey(filename string, pubkey *rsa.PublicKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.Encode(file, block)
}

func loadPEMKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyData)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPublicPEMKey(filename string) (*rsa.PublicKey, error) {
	publicKeyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyData)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
}

func signMessage(privateKey *rsa.PrivateKey, message string) ([]byte, error) {
	hash := sha256.New()
	hash.Write([]byte(message))
	hashedMessage := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, privateKey, 0, hashedMessage)
}

func verifySignature(publicKey *rsa.PublicKey, message string, signature []byte) error {
	hash := sha256.New()
	hash.Write([]byte(message))
	hashedMessage := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, 0, hashedMessage, signature)
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	publicKey := &privateKey.PublicKey

	savePEMKey("private.pem", privateKey)
	savePublicPEMKey("public.pem", publicKey)
	fmt.Println("Ключи сгенерированы и сохранены в private.pem public.pem")

	fmt.Println("Введите сообщение, которое хотите подписать")
	message, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	message = strings.TrimSpace(message)

	signature, err := signMessage(privateKey, message)
	if err != nil {
		fmt.Println("Ошибка подписания")
		return
	}
	fmt.Println("Сообщение подписано")

	loadedPublicKey, err := loadPublicPEMKey("public.pem")
	if err != nil {
		fmt.Println("Ошибка загрузки открытого ключа")
		return
	}

	err = verifySignature(loadedPublicKey, message, signature)
	if err != nil {
		fmt.Println("Подпись недействительна")
	} else {
		fmt.Println("Подпись проверена и является действителньой")
	}

}
