package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"openpgp/utils"
)

var (
	directory       string
	name            string
	comment         string
	email           string
	bitsKey         int
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

			// Encriptar arquivo
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

	case flag.Arg(0) == "decrypt":

		if privKey == "" {
			fmt.Println("Error: -privKey is required")
			usage()
			return
		}

		fs := flag.NewFlagSet("decrypt [flags]", flag.ExitOnError)

		fs.StringVar(&fileToDecrypt, "file", "", "[File to decrypt]")
		verify := fs.Bool("verify", false, "[Enter password to sign decrypted file]")

		fs.Parse(flag.Args()[1:])

		if *verify {
			if pubKey == "" {
				fmt.Println("Error: -pubKey is required")
				usage()
				return
			}

			for passphrase == "" {
				fmt.Print("Passphrase: ")
				fmt.Scanln(&passphrase)
			}
			err := utils.DecrytptVerifyMessageArmored(pubKey, privKey, passphrase, fileToDecrypt)
			if err != nil {
				log.Fatal(err.Error())
			}
		} else {
			fmt.Print("Passphrase (''): ")
			fmt.Scanln(&passphrase)
			err := utils.DecryptMessageArmored(privKey, fileToDecrypt, passphrase)
			if err != nil {
				log.Fatal(err.Error())
			}
		}

	case flag.Arg(0) == "keygen":

		fs := flag.NewFlagSet("keygen [Generates a new pub/priv key pair]", flag.ExitOnError)

		fs.StringVar(&keyOutputDir, "d", ".keys/", "Directory of keys files")
		pass := fs.Bool("passphrase", false, "[Define passphrase is on]")
		expTime := fs.Bool("expiration", false, "[Define expiration time of the key is on]")

		fs.Parse(flag.Args()[1:])

		// Caminho do arquivo de salvamento das chaves
		fmt.Printf("Directory and prefix keys ('./key-defaultname') ")
		fmt.Scanln(&directory)
		if directory == "" {
			directory = ".key-defaultname"
		}

		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Name: ")
		name, _ = reader.ReadString('\n')

		fmt.Print("Comment: ")
		comment, _ = reader.ReadString('\n')

		for {
			fmt.Printf("Email adress: ")
			fmt.Scanln(&email)
			if ok := utils.ValidateEmail(email); !ok {
				fmt.Println("Valid email, type again: ")
				continue
			} else {
				break
			}
		}

		fmt.Printf("Your User ID is: \n \n %s (%s) <%s>\"\n", strings.TrimSpace(name), strings.TrimSpace(comment), strings.TrimSpace(email))

		for bitsKey != 1024 && bitsKey != 2048 && bitsKey != 4096 {
			fmt.Println("Number bites of the keys: \n[1024 bits] [2048 bits] [4096 bits]")
			fmt.Printf("Type the size (2048): ")
			fmt.Scanln(&bitsKey)
			if bitsKey == 0 {
				bitsKey = 2048
			}
		}

		if *pass {
			fmt.Printf("Passphrase(''): ")
			fmt.Scanln(&passphrase)
		}

		for {
			if *expTime {
				fmt.Println(`
			Specify how long the key should be valid
			<n>0 = key not expires
			<n>d = key expires n days
			<n>w = key expires n weeks
			<n>m = key expires n months
			<n>y = key expires n years`)
				fmt.Printf("Is the key valid for? (0) ")
				fmt.Scanln(&expirationInput)
				if expirationInput != "" {
					dataExp, err := utils.ParseKeyDuration(expirationInput)
					if err != nil {
						fmt.Println("Invalid input: ", err)
						continue
					}
					fmt.Printf("Key expires: %s", dataExp.Format("02/02/2006 15:04:05"))
					expirationTime = dataExp
					break
				} else {
					expirationInput = "0"
					fmt.Println("Key not expires.")
					break
				}
			}
		}

		err := utils.GenerateKeys(directory, name, comment, email, passphrase, &expirationTime, bitsKey)
		if err != nil {
			log.Fatal(err)
		}

	default:
		usage()
		return
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
