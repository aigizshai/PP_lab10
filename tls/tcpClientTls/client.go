package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		fmt.Println("Ошибка при загрузке клиентского сертификата")
		os.Exit(1)
	}

	serverCertPool := x509.NewCertPool()
	serverCert, err := ioutil.ReadFile("server.crt")
	if err != nil {
		fmt.Println("Ошибка при чтении сертификата сервера")
		os.Exit(1)
	}
	serverCertPool.AppendCertsFromPEM(serverCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      serverCertPool,
		ServerName:   "",
	}

	conn, err := tls.Dial("tcp", ":8080", tlsConfig)
	if err != nil {
		fmt.Println("Ошибка подключения ", err)
		os.Exit(1)
	}
	defer conn.Close()
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Введите сообщения ")
	message, _ := reader.ReadString('\n')
	fmt.Fprintf(conn, message)

	response, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println("Ответ от сервера ", response)
}
