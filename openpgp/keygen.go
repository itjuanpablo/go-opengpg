package openpgp

import (
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// GenerateKeyPair gera o par de chaves pub/priv
func GenerateKeyPair(name, email string) error {
	// Abrir o arquivo para gravar a chave privada
	privateKeyFile, err := os.Create("private_key.gpg")
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	// Abrir o arquivo para gravar a chave pública
	publicKeyFile, err := os.Create("public_key.gpg")
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	// Configurações para geração da chave
	config := &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionNone,
		// DefaultHash:            packet.SHA256,
		RSABits: 2048,
		Time:    nil, // Hora atual
		// Algorithm: []uint8{
		// 	packet.PubKeyAlgoDSA,
		// 	packet.PubKeyAlgoEdDSA,
		// 	packet.PubKeyAlgoECDSA,
		// },
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
