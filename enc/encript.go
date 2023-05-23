package enc

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Variávies de ambiente
const (
	mySecretString     = "This is so very secret!"
	prefix, passphrase = "/files", "teste"
	secretKeyring      = prefix + "/keys/riversoft_privkey.gpg"
	publicKeyring      = prefix + "/keys/riversoft_pubkey.gpg"
)

// EncTest faz a encriptação do arquivo a partir da chave privada
func EncTest(secretString string) (string, error) {
	log.Println("Secret to hide:", secretString)
	log.Println("Public Keyring:", publicKeyring)

	// Leitura da chave pública
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}

	// Encriptar string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(mySecretString))
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	// Encode to base64
	bytes, err := io.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	// Saída string enrypted/encoded
	log.Println("Encrypted Secret:", encStr)

	return encStr, nil
}

func decTest(encString string) (string, error) {
	log.Println("Secret Keyring:", secretKeyring)
	log.Println("Passphrase:", passphrase)

	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	entity = entityList[0]

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	passphraseByte := []byte(passphrase)
	log.Println("Decrypting private key using passphrase")
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}
	log.Println("Finished decrypting private key using passphrase")

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}

func main() {
	encStr, err := EncTest(mySecretString)
	if err != nil {
		log.Fatal(err)
	}
	decStr, err := decTest(encStr)
	if err != nil {
		log.Fatal(err)
	}
	// should be done
	log.Println("Decrypted Secret:", decStr)
}
