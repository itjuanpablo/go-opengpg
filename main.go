package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"openpgp/utils"
)

var (
	directory       string
	name            string
	comment         string
	email           string
	bits            string
	passphrase      string
	expirationInput string
	expirationTime  time.Time
)

var privKey, pubKey, keyOutputDir, fileToEncrypt, fileToDecrypt string

func main() {
	// Flags de uso
	flag.StringVar(&privKey, "privKey", "", "[Directory where the private key is located]")
	flag.StringVar(&pubKey, "pubKey", "", "[Directory where the public key is located]")
	flag.Parse()

	// Mensagem de erro caso nenhuma flag setada seja para encriptar, decriptar ou gerar o par de chaves
	if flag.NArg() == 0 || (flag.Arg(0)) != "encrypt" && (flag.Arg(0) != "decrypt" && flag.Arg(0) != "keygen") {
		errorMessage := "Error: Subcommand " + flag.Arg(0) + "is not available"
		fmt.Println(errorMessage)
		usage()
		return
	}

	switch {
	case flag.Arg(0) == "encrypt":
		if pubKey == "" {
			fmt.Println("Error: -pubKey is required")
			usage()
			return
		}
	}

	fs := flag.NewFlagSet("encrypt [flags]", flag.ExitOnError)

	fs.StringVar(&fileToEncrypt, "file", "", "[File to encrypt]")
	sygn := fs.Bool("sygn", false, "[Enter password to sign encrypted file]")

	fs.Parse(flag.Args()[1:])

	if *sygn {
		if privKey == "" {
			fmt.Println("Error: -privKey is required")
			usage()
			return
		}

		for passphrase == "" {
			fmt.Print("Passphrase for sygn: ")
			fmt.Scanln(&passphrase)
		}

		// Encriptar chave
		err := utils.EncryptSygnMessageArmored(pubKey, privKey, passphrase, fileToEncrypt)
		if err != nil {
			log.Fatal(err.Error())
		}
	} else {
		err := utils.EncryptFileArmored(pubKey, fileToEncrypt)
		if err != nil {
			log.Fatal(err.Error())
		}
	}
}

func usage() {
	fmt.Println()
	fmt.Println("Available flags before subcommands encrypt or decrypt:")
	fmt.Println("  -privKey string: specify secretKey")
	fmt.Println("  -pubKey string: specify publicKey")
	fmt.Println()
	fmt.Println("Available flags after subcommand encrypt:")
	fmt.Println("  -file string: specify file to encrypting process")
	fmt.Println()
	fmt.Println("Available flags after subcommand encrypt:")
	fmt.Println("  -file string: specify file to decrypting process")
	fmt.Println()
	fmt.Println("Available flags after subcommand keygen:")
	fmt.Println("  -passphrase string: Define if passphrase is on")
	fmt.Println("  -expiration string: Define if keys expiration time is on")
	fmt.Println()
}
