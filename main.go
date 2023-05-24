package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"stcpsyncpgp/openpgp"
)

// Definição os dados a serem preenchidos
var name, comment, email, directory string

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Name: ")
		name, _ = reader.ReadString('\n')
		name = strings.TrimSpace(name)

		fmt.Print("Comment: ")
		email, _ = reader.ReadString('\n')
		email = strings.TrimSpace(comment)

		fmt.Print("DirectoryPath: ")
		directory, _ = reader.ReadString('\n')
		directory = strings.TrimSpace(directory)

		fmt.Print("Email: ")
		email, _ = reader.ReadString('\n')
		email = strings.TrimSpace(email)
		if openpgp.ValidateEmail(email) {
			break
		} else {
			fmt.Println("Email inválido. Por favor, insira um email válido")
		}
	}

	openpgp.GenerateKeyPair(name, email, directory)
}
