package openpgp

import (
	"crypto"
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// GenerateKeyPair gera o par de chaves pub/priv
func GenerateKeyPair(name, email string) error {
	// Abrir o arquivo para gravar a chave privada
	privateKeyFileName := name + "_private_key.gpg"
	privateKeyFile, err := os.Create(privateKeyFileName)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	// Abrir o arquivo para gravar a chave pública
	publicKeyFileName := name + "_public_key.gpg"
	publicKeyFile, err := os.Create(publicKeyFileName)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	// Configurações da entidade
	config := &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		DefaultHash:            crypto.SHA256,
		RSABits:                2048,
		// Time:    nil, // Hora atual
	}

	// Gerar par de chaves
	entity, err := openpgp.NewEntity(name, "", email, config)
	if err != nil {
		return err
	}

	// Escrever a chave privada
	err = entity.SerializePrivate(privateKeyFile, nil)
	if err != nil {
		fmt.Println("Não foi possível escrever a chave privada")
	}

	// Escrever a chave pública no arquivo
	err = entity.Serialize(publicKeyFile)
	if err != nil {
		fmt.Println("Não foi possível escrever a chave pública")
	}

	fmt.Println("Par de chaves gerado com sucesso!")
	return nil
}
