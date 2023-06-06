package utils

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// EncryptFileArmored encripta um arquivo de chave pública, convertendo seu conteúdo de `bites` para `armored` após ler o conteúdo do arquivo de chave pública
func EncryptFileArmored(key, directory string) error {
	// Ler conteúdo do arquivo
	keyBitesContent, err := ioutil.ReadFile(key)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return err
	}
	keyStringContent := string(keyBitesContent)

	// Ler conteúdo do arquivo
	fileBitesContent, err := ioutil.ReadFile(directory)
	if err != nil {
		if err != nil {
			fmt.Println("Error reading file:", err)
			return err
		}
	}
	fileStringContent := string(fileBitesContent)

	armor, err := helper.EncryptMessageArmored(keyStringContent, fileStringContent)
	if err != nil {
		return err
	}

	// Escrever chave pública no arquivo lido
	pubKeyFile, err := os.Create(directory + ".gpg")
	if err != nil {
		return err
	}
	defer pubKeyFile.Close()

	// Converter de byte para armored
	_, err = pubKeyFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	// Printar mensagem de arquivo criptografado
	fmt.Println("Successfully encrypted file")

	return nil
}

func EncryptSignMessageArmored(pubKey, privKey, passphrase, directory string) error {
	// Ler conteúdo do arquivo
	pubkeyBitesContent, err := ioutil.ReadFile(pubKey)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return err
	}
	pubKeyStringContent := string(pubkeyBitesContent)

	privKeyBitesContent, err := ioutil.ReadFile(privKey)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return err
	}
	privKeyStringContent := string(privKeyBitesContent)

	// Ler conteúdo do arquivo
	fileBitesContent, err := ioutil.ReadFile(directory)
	if err != nil {
		if err != nil {
			fmt.Println("Error reading file:", err)
			return err
		}
	}
	fileStringContent := string(fileBitesContent)

	armor, err := helper.EncryptSignMessageArmored(pubKeyStringContent, privKeyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	// Escrever chave pública no arquivo lido
	pubKeyFile, err := os.Create(directory + ".gpg")
	if err != nil {
		return err
	}
	defer pubKeyFile.Close()

	// Converter de byte para armored
	_, err = pubKeyFile.Write([]byte(armor))
	if err != nil {
		return err
	}

	// Printar mensagem de arquivo criptografado
	fmt.Println("Successfully encrypted file")

	return nil
}
