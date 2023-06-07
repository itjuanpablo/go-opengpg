package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Acessar local do arquivo onde o par de chaves
// Ler conteúdo das chaves
// Verificar se é uma chave OpenPGP
// Verificar expiração da chave

func CheckKeys(keyFile string) error {
	// Abrir arquivo
	file, err := os.Open(keyFile)
	if err != nil {
		return fmt.Errorf("Falha ao abrir arquivo de chave", err)
	}
	defer file.Close()

	// Ler arquivo de chave
	entityList, err := openpgp.ReadArmoredKeyRing(file)
	if err != nil {
		return fmt.Errorf("Falha ao ler arquivo de chave", err)
	}

	// Verificar se é uma chave válida
	entity := entityList[0]
	privKey := entity.PrivateKey
	if privKey == nil {
		return fmt.Errorf("Não foi fornecida uma chave privada")
	}

	var expires time.Time
	// for _, ident := range entity.Identities {
	// 	if ident.SelfSignature != nil && ident.SelfSignature.KeyLifetimeSecs > 0 {
	// 		creationTime := ident.SelfSignature.CreationTime
	// 		lifetimeSecs := time.Duration(ident.SelfSignature.KeyLifetimeSecs) * time.Second
	// 		expires = creationTime.Add(lifetimeSecs)
	// 		break
	// 	}
	// }

	// Verifica se a chave não tem data de expiração
	if expires.IsZero() {
		fmt.Println("A chave não possui data de expiração")
	} else {
		fmt.Printf("A chave expira em: %s\n", expires.Format(time.RFC3339))
	}

	return nil
}
