package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {

	for {
		fmt.Println("Выберетие пункт меню:")
		fmt.Println("1. Захешировать строку sha-256")
		fmt.Println("2. Захешировать строку md5")
		fmt.Println("3. Захешировать строку sha-512")
		fmt.Println("4. Проверить целостность данных")
		fmt.Println("0. Выход")

		var choise int
		fmt.Scan(&choise)
		switch choise {
		case 1:
			doHashSha256()
		case 2:
			doHashMd5()
		case 3:
			doHashSha512()
		case 4:
			verify()
		case 0:
			os.Exit(0)
		default:
			fmt.Println("Неккоректный ввод")
		}
	}
}

func doHashSha256() {
	fmt.Println("Введите строку")
	var str string
	str, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	str = strings.TrimSpace(str)

	h := sha256.New()
	h.Write([]byte(str))
	hexhash := hex.EncodeToString(h.Sum(nil))
	fmt.Println("Хеш строки")
	fmt.Println(hexhash)
}

func doHashMd5() {
	fmt.Println("Введите строку")
	var str string
	str, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	str = strings.TrimSpace(str)

	h := md5.New()
	h.Write([]byte(str))
	hexhash := hex.EncodeToString(h.Sum(nil))
	fmt.Println("Хеш строки")
	fmt.Println(hexhash)
}

func doHashSha512() {
	fmt.Println("Введите строку")
	var str string
	str, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	str = strings.TrimSpace(str)

	h := sha512.New()
	h.Write([]byte(str))
	hexhash := hex.EncodeToString(h.Sum(nil))
	fmt.Println("Хеш строки")
	fmt.Println(hexhash)
}

func verify() {
	fmt.Println("Выберите хеш функцию, которой захеширована строка")
	fmt.Println("1. md5")
	fmt.Println("2. sha-256")
	fmt.Println("3. sha-512")
	var choise int
	fmt.Scan(&choise)
	switch choise {
	case 1:
		fmt.Println("Введите строку")
		var str string
		str, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		str = strings.TrimSpace(str)
		fmt.Println("Теперь введите ее хеш")
		var h string
		h, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		h = strings.TrimSpace(h)

		hs := md5.New()
		hs.Write([]byte(str))
		hexhash := hex.EncodeToString(hs.Sum(nil))

		if h == hexhash {
			fmt.Println("Хеш-функции совпадают")
		} else {
			fmt.Println("Хеш-функции не совпадают")
		}
	case 2:
		fmt.Println("Введите строку")
		var str string
		str, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		str = strings.TrimSpace(str)
		fmt.Println("Теперь введите ее хеш")
		var h string
		h, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		h = strings.TrimSpace(h)

		hs := sha256.New()
		hs.Write([]byte(str))
		hexhash := hex.EncodeToString(hs.Sum(nil))

		if h == hexhash {
			fmt.Println("Хеш-функции совпадают")
		} else {
			fmt.Println("Хеш-функции не совпадают")
		}
	case 3:
		fmt.Println("Введите строку")
		var str string
		str, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		str = strings.TrimSpace(str)
		fmt.Println("Теперь введите ее хеш")
		var h string
		h, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		h = strings.TrimSpace(h)

		hs := sha512.New()
		hs.Write([]byte(str))
		hexhash := hex.EncodeToString(hs.Sum(nil))

		if h == hexhash {
			fmt.Println("Хеш-функции совпадают")
		} else {
			fmt.Println("Хеш-функции не совпадают")
		}
	}
}
