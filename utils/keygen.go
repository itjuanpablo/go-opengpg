package utils

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// GenerateKeyPair gera o par de chaves pub/priv
func GenerateKeyPair(name, email, directory string, expiration time.Time) error {
	// Verificar se o diretório fornecido existe
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		// Criar o diretório se não existir
		err := os.MkdirAll(directory, 0o755)
		if err != nil {
			return err
		}
	}

	// Nome base dos arquivos de chaves
	baseFileName := name + "_key"

	// Caminhos completos para os arquivos
	privateKeyFilePath := filepath.Join(directory, baseFileName+"_private.gpg")
	publicKeyFilePath := filepath.Join(directory, baseFileName+"_public.gpg")

	// Abrir o arquivo para gravar a chave privada
	privateKeyFile, err := os.Create(privateKeyFilePath)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	// Abrir o arquivo para gravar a chave pública

	publicKeyFile, err := os.Create(publicKeyFilePath)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	expirationInSeconds := expiration.Unix() - time.Now().Unix()

	// Configurações da entidade
	config := &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		DefaultHash:            crypto.SHA256,
		RSABits:                2048,
		KeyLifetimeSecs:        uint32(expirationInSeconds), // Data de expiração da chave
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
