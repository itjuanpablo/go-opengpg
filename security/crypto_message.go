package security

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
)

// EncriptKey faz a leitura da chave pública gerada para criptografar uma mensagem aleatória
func EncriptKey() {
	publicKey, err := os.Open("files/Juan Pablo_public.asc")
	if err != nil {
		fmt.Println("Erro ao ler a chave pública")
	}
	defer publicKey.Close()

	readArmored, err := openpgp.ReadArmoredKeyRing(publicKey)
	if err != nil {
		fmt.Println(err)
	}

	message := []byte("Tudo ok!")
	encryptedMessage := new(bytes.Buffer)

	plaintext, err := openpgp.Encrypt(encryptedMessage, readArmored, nil, nil, nil)
	if err != nil {
		fmt.Println("Erro ao criptografar a mensagem", err)
	}
	plaintext.Write(message)
	plaintext.Close()

	fmt.Println("Mensagem criptografada:", encryptedMessage.String())
}

// DecriptKey utiliza a chave privada para descriptografar uma mensagem aleatória
func DecriptKey(encryptedMessage *bytes.Buffer) error {
	privateKeyASC, err := os.Open("files/Juan Pablo Ladeira_SECRET.asc")
	if err != nil {
		fmt.Println("Erro ao abrir a chave privada")
	}
	defer privateKeyASC.Close()

	privateKeyRing, err := openpgp.ReadArmoredKeyRing(privateKeyASC)
	if err != nil {
		fmt.Println("Erro ao fazer a leitura da chave privada")
	}

	decryptedMessage, err := openpgp.ReadMessage(encryptedMessage, privateKeyRing, nil, nil)
	if err != nil {
		fmt.Println("Erro ao descriptografar a mensagem: ", err)
	}

	decryptedBytes, err := io.ReadAll(decryptedMessage.UnverifiedBody)
	if err != nil {
		fmt.Println("Erro ao ler a mensagem descriptografada: ", err)
	}

	fmt.Println("Mensagem descriptada: ", string(decryptedBytes))
	return nil
}
