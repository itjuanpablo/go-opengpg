package utils

import (
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func verifyOpenPGPKey(keyringFile string, keyID string) error {
	// Abra o arquivo de keyring (anéis de chave) OpenPGP
	file, err := os.Open(keyringFile)
	if err != nil {
		return fmt.Errorf("falha ao abrir o arquivo de keyring: %s", err)
	}
	defer file.Close()

	// Leia o keyring OpenPGP
	entityList, err := openpgp.ReadKeyRing(file)
	if err != nil {
		return fmt.Errorf("falha ao ler o keyring: %s", err)
	}

	// Encontre a entidade com base no ID da chave
	entity, ok := entityList.KeysById(keyID)
	if !ok {
		return fmt.Errorf("chave não encontrada no keyring")
	}

	// Verifique a validade da chave
	err = entity[0].Entity.PrimaryKey.VerifyUserIdSignature(entity[0].Entity.Identity.Name, entity[0].Entity.Identity.UserId.Id, nil)
	if err != nil {
		return fmt.Errorf("falha na verificação da chave: %s", err)
	}

	fmt.Println("Chave válida e verificada com sucesso!")
	return nil
}

// func main() {
// 	keyringFile := "caminho/para/o/keyring.gpg"
// 	keyID := "ID_DA_CHAVE"

// 	err := verifyOpenPGPKey(keyringFile, keyID)
// 	if err != nil {
// 		fmt.Println("Erro:", err)
// 		return
// 	}
