package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"stcpsyncpgp/openpgp"
)

// Variáveis principais
var (
	name       string
	comment    string
	email      string
	directory  string
	passphrase string
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	genKeyFlag := flag.Bool("genkey", false, "Generate public/private OpenPGP key pair")

	// Parsear as flags da linha de comando
	flag.Parse()

	if *genKeyFlag {
		fmt.Println("Generate public/private opengpg key pair.")
		fmt.Print("Enter directory in which to save the key (Example: C:/keys/): ")
		directory, _ = reader.ReadString('\n')
		directory = strings.TrimSpace(directory)

		fmt.Print("Enter passphrase (empty for no passphrase): ")
		passphrase, _ = reader.ReadString('\n')
		passphrase = strings.TrimSpace(passphrase)

		fmt.Print("Enter the key name: ")
		name, _ = reader.ReadString('\n')
		name = strings.TrimSpace(name)

		fmt.Print("Comment: ")
		comment, _ = reader.ReadString('\n')
		comment = strings.TrimSpace(comment)

		for {
			fmt.Print("Email: ")
			email, _ = reader.ReadString('\n')
			email = strings.TrimSpace(email)
			if openpgp.ValidateEmail(email) {
				break
			} else {
				fmt.Println("Invalid email. (example@email.com)")
			}

		}

		openpgp.GenerateKeyPair(name, email, directory)

		return
	}
}
