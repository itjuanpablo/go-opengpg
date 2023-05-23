package main

import (
	"fmt"

	"stcpsyncpgp/openpgp"
)

// Definição os dados a serem preenchidos
var name, comment, email string

func main() {
	for {
		fmt.Print("Name: ")
		fmt.Scan(&name)

		fmt.Print("Comment: ")
		fmt.Scan(&comment)

		fmt.Print("Email: ")
		fmt.Scan(&email)
		if openpgp.ValidateEmail(email) {
			break
		} else {
			fmt.Println("Email inválido. Por favor, insira um email válido")
		}
	}

	openpgp.GenerateKeyPair(name, email)
}
