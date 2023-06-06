package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func DecryptMessageArmored(key, directory, passphrase string) error {
	// Ler conteúdo do arquivo
	keyBitesContent, err := os.ReadFile(filepath.Join(key))
	if err != nil {
		fmt.Println("Error reading file:", err)
		return err
	}
	keyStringContent := string(keyBitesContent)

	// Ler conteúdo do arquivo
	fileBitesContent, err := os.ReadFile(filepath.Join(directory))
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
	pubKeyFile, err := os.Create(filepath.Join(filepath.Dir(directory), "decrypted.txt"))
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
	fmt.Println("Successfully descrypted file")

	return nil
}

func DecrytptVerifyMessageArmored(pubkey, privKey, passphrase, directory string) error {
	// Abrir arquivo de chave pública
	pubKeyFile, err := os.Open(pubkey)
	if err != nil {
		fmt.Printf("Error reading file:%s", err)
		return err
	}
	defer pubKeyFile.Close()

	// Ler conteúdo da chave
	pubKeyBitesContent, err := io.ReadAll(pubKeyFile)
	if err != nil {
		if err != nil {
			return err
		}
	}
	pubKeyStringContent := string(pubKeyBitesContent)

	// Ler conteúdo da chave
	privKeyFile, err := os.Open(privKey)
	if err != nil {
		fmt.Printf("Error reading file:%s", err)
		return err
	}
	defer privKeyFile.Close()

	privKeyBitesContent, err := io.ReadAll(privKeyFile)
	if err != nil {
		return err
	}
	privKeyStringContent := string(privKeyBitesContent)

	fileToEncrypt, err := os.Open(directory)
	if err != nil {
		fmt.Printf("Error reading file:%s", err)
		return err
	}
	defer fileToEncrypt.Close()

	fileBitesContent, err := io.ReadAll(fileToEncrypt)
	if err != nil {
		return err
	}
	fileStringContent := string(fileBitesContent)

	armor, err := helper.DecryptVerifyMessageArmored(pubKeyStringContent, privKeyStringContent, []byte(passphrase), fileStringContent)
	if err != nil {
		return err
	}

	// Escrever chave pública no arquivo lido
	pubKeyFile, err = os.Create(filepath.Join(filepath.Dir(directory), "decrypted.txt"))
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
	fmt.Println("Successfully descrypted file")

	return nil
}
