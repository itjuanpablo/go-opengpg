package main

import (
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/alecthomas/kingpin/v2"
)

var (

	// Goencrypt app
	app           = kingpin.New("goencrypt", "A command line tool for encrypting files")
	bits          = app.Flag("bits", "Bits for keys").Default("4096").Int()
	privateKey    = app.Flag("private", "Private key").String()
	publicKey     = app.Flag("public", "Public key").String()
	signatureFile = app.Flag("sig", "Signature File").String()

	// Generates new public and private keys
	keyGenCmd       = app.Command("keygen", "Generates a new public/private key pair")
	keyOutputPrefix = keyGenCmd.Arg("prefix", "Prefix of key files").Required().String()
	keyOutputDir    = keyGenCmd.Flag("d", "Output directory of key files").Default("keys").String()

	// Encrypts a file with a public key
	encryptionCmd = app.Command("encrypt", "Encrypt from stdin")

	// Signs a file with a private key
	signCmd = app.Command("sign", "Sign stdin")

	// Verifies a file was signed with the public key
	verifyCmd = app.Command("verify", "Verify a signature of stdin")

	// Decrypts a file with a private key
	decryptionCmd = app.Command("decrypt", "Decrypt from stdin")
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	// Gerar chaves
	case keyGenCmd.FullCommand():
		GenerateKeys()
	// case createEntityCmd.FullCommand():
	// 	newEntity()
	case encryptionCmd.FullCommand():
		EncryptFile()
	case signCmd.FullCommand():
		SignFile()
	case verifyCmd.FullCommand():
		VerifyFile()
	case decryptionCmd.FullCommand():
		DecrypteFile()
	default:
		kingpin.FatalUsage("Unknown command")
	}
}

// EncodePrivateKey é responsável por codificar uma chave privada RSA em formato OpenPGP e gravá-la em um escritor
func EncodePrivateKey(out io.Writer, key *rsa.PrivateKey) {
	// Criar camada de codificação com o OpenPGP Armor no escritor "out" com um mapa vazio
	w, err := armor.Encode(out, openpgp.PrivateKeyType, make(map[string]string))
	if err != nil {
		log.Fatalf("Error creating OpenPGP Armor: %s", err)
	}

	// Novo objeto do tipo `packet.RSAPrivateKey`criado na variável "pgpKey", logo depois ocorre a serialização e gravação no escritor "w"
	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
	if err = pgpKey.Serialize(w); err != nil {
		log.Fatalf("Error serializing private key: %s", err)
	}

	// Finalização da escrita da chave privada codificada. Se der erro, `FatalIfError` retorna-o
	kingpin.FatalIfError(w.Close(), "Error serializing private key: %s", err)
}

// DecodePrivateKey é responsável pela decodificação de um arquivo de chave privada, em formato OpenPGP, retornando a chave privada como um objeto `*packet.PrivateKey`
func DecodePrivateKey(filename string) *packet.PrivateKey {
	// Caminho do arquivo na variável filename é aberto, o retorno é atribuído a variável `in`
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening private key: %s", err)

	// Se ocorrer algum erro, o arquivo será fechado
	defer in.Close()

	// Decodificar a camada de codificação OpenPGP do arquivo na variável `in`, o resultado é atribuído na variável `block`
	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	// O tipo de bloco precisa ser igual a openpgp.PrivateKeyType(representa o tipo de chave privada), se for diferente, o arquivo não contem uma chave privada válida.
	if block.Type != openpgp.PrivateKeyType {
		log.Fatalf("Invalid private key file: Error decoding private key")
	}

	// Um novo leitor é criado `reader`, usando o corpo do bloco codificado `block.Body`, Next() é chamada para o leitor obter o próximo pacote de dados. O pacote resultante é atrubúido a variável `pkt`
	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	//`pkt` é convertido para o tipo *packet.PrivateKey na variável `key`
	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		log.Fatalf("Invalid private key: Error parsing private key")
	}

	// Retorna a chave privada
	return key
}

// DecodePublicKey é responsável por decodificar um arquivo de chave pública OpenPGP, e retorna essa mesma chave como um objeto `*packet.PublicKey`
func DecodePublicKey(filename string) *packet.PublicKey {
	// Abrir o arquivo no caminho `filename` o retorno é atribuído a `in`
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)

	// Se ocorrer algum erro, o arquivo será fechado
	defer in.Close()

	// Decodificar a camada de codificação OpenPGP do arquivo na variável `in`, o resultado é atribuído na variável `block`
	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	// O tipo de bloco precisa ser igual a openpgp.PrivateKeyType(representa o tipo de chave privada), se for diferente, o arquivo não contem uma chave pública válida.
	if block.Type != openpgp.PublicKeyType {
		log.Fatalf("Invalid private key file: Error decoding private key")
	}

	// Um novo leitor é criado `reader`, usando o corpo do bloco codificado `block.Body`, Next() é chamada para o leitor obter o próximo pacote de dados. O pacote resultante é atrubúido a variável `pkt`
	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	//`pkt` é convertido para o tipo *packet.PrivateKey na variável `key`
	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		log.Fatalf("Invalid public key: Error parsing public key")
	}

	// Retorna a chave
	return key
}

// EncodePublicKey é responsável por codificar uma chave pública RSA em formato OpenPGP e gravá-la em um escritor
func EncodePublicKey(out io.Writer, key *rsa.PrivateKey) {
	// Criar uma camada de codificação OpenPGP no escritor `out` e um mapa vazio de cabeçalhos são fornecidos como parâmetros
	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)

	// Novo objeto é criado, do tipo packet.RSAPublicKey, recebendo data e hora e um ponteiro para a chave pública. Logo depois ocorre a serialização e gravação no escritor "w".
	pgpKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	kingpin.FatalIfError(pgpKey.Serialize(w), "Error serializing public key: %s", err)

	// Finalizar escrita da chave pública codificada
	kingpin.FatalIfError(w.Close(), "Error serializing public key: %s", err)
}

// DecodeSignature decodificar um arquivo de assinatura codificado em formato OpenPGP e retornar a assinatura como um objeto `*packet.Signature`
func DecodeSignature(filename string) *packet.Signature {
	// Abre o arquivo contendo a assinatura a ser codificada
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)

	// Garantir o arquivo fechado após o uso
	defer in.Close()

	// Decodificar a camada de codificação OpenPGP do arquivo `in`
	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	// O tipo de bloco precisa ser igual a openpgp.PrivateKeyType(representa o tipo de chave privada), se for diferente, o arquivo não contem uma chave assinatura válida
	if block.Type != openpgp.SignatureType {
		log.Fatalf("Invalid signature file: Error parsing signature")
	}

	// Um novo leitor é criado `reader`, usando o corpo do bloco codificado `block.Body`, Next() é chamada para o leitor obter o próximo pacote de dados. O pacote resultante é atrubúido a variável `pkt`
	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading signature")

	//`sig` é convertido para o tipo *packet.PrivateKey na variável `key`
	sig, ok := pkt.(*packet.Signature)
	if !ok {
		log.Fatalf("Invalid signature: Error parsing signature")
	}

	// Retorno da assinatura
	return sig
}

// EncryptFile faz a encriptação do arquivo usando OpenPGP
func EncryptFile() {
	pubkey := DecodePublicKey(*publicKey)
	privKey := DecodePrivateKey(*privateKey)

	// Uma entidade OpenPGP é criada usando as chaves pública e privada decodificadas
	to := CreateEntityFromKeys(pubkey, privKey)

	// Camada para codificação OpenGPG, recebendo um objeto `io.Writer` para escrever a saída, com um map opcional no cabeçalho. Resultado é atribuído a `w`
	w, err := armor.Encode(os.Stdout, "Message", make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenpPGP Armor: %s", err)

	// Inicar processo de criptografia, para escrever a saída criptografada, uma lista de entidades(`to`) represetando os destinatários e opções adicionais
	plain, err := openpgp.Encrypt(w, []*openpgp.Entity{to}, nil, nil, nil)
	kingpin.FatalIfError(err, "Error creating entity for encryption")
	defer plain.Close()

	// Realizar compressão dos dados criprtografados. Recebe o obejto `plain`
	compressed, err := gzip.NewWriterLevel(plain, gzip.BestCompression) //  gzip.BestCompression para obter a melhor taxa de compressão possível
	kingpin.FatalIfError(err, "Invalid compression level")

	// Os dados são lidos a partir do `os.Stdin`, usando `io.Copy`. Logo após os dados são copiados para `compressed`, que realiza a compressão e escreve os dados criptografados no objeto plain. O número total de bytes lidos é armazenado em `n`.
	n, err := io.Copy(compressed, os.Stdin)
	kingpin.FatalIfError(err, "Error writing encrypted file")
	kingpin.Errorf("Encrypted %d bytes", n)

	// Fecha `compressed` para garantir que todos dados sejam gravados corretamente,
	compressed.Close()
}

// DecrypteFile é responsável por descriptografar um arquivo criptografado usando a criptografia OpenPGP
func DecrypteFile() {
	// Decodificar as chaves pública e privada, respectivamente. Os valores decodificados são armazenados nas variáveis pubkey e privKey.
	pubkey := DecodePublicKey(*publicKey)
	privKey := DecodePrivateKey(*privateKey)

	// Cria uma entidade com as chaves públicas e privada
	entity := CreateEntityFromKeys(pubkey, privKey)

	// Decodificar a camada de codificação presente em `os.Stdin`
	block, err := armor.Decode(os.Stdin)
	kingpin.FatalIfError(err, "Error reading OpenPGP Armor: %s", err)

	// O tipo de block tem que ser igual a "Message"
	if block.Type != "Message" {
		kingpin.FatalIfError(err, "Invalid message type")
	}

	// Uma lista de entidades `entityList` é criada e a entidade `entity` é adicionada a ela. A lista de entidades é necessária para descriptografar a mensagem.
	var entityLIst openpgp.EntityList
	entityLIst = append(entityLIst, entity)

	// `openpgp.ReadMessage` é chamada para ler a mensagem descriptografada
	md, err := openpgp.ReadMessage(block.Body, entityLIst, nil, nil)
	kingpin.FatalIfError(err, "Error reading message")

	// É criado para descomprimir os dados da mensagem descriptografada. Ele recebe o corpo não verificado da mensagem (md.UnverifiedBody) como entrada
	compressed, err := gzip.NewReader(md.UnverifiedBody)
	kingpin.FatalIfError(err, "Invalid compression level")
	defer compressed.Close()

	// Os dados descomprimidos são copiados para a saída padrão (os.Stdout) usando a função `io.Copy`. O número total de bytes copiados é armazenado em `n`.
	n, err := io.Copy(os.Stdout, compressed)
	kingpin.FatalIfError(err, "Error reading encrypted file")
	kingpin.Errorf("Decrypted %d bytes", n)
}

// SignFile é responsável por assinar um arquivo usando uma chave privada OpenPGP
func SignFile() {
	// Decodificar chaves pub/priv
	pubkey := DecodePublicKey(*publicKey)
	privKey := DecodePrivateKey(*privateKey)

	// Uma entidade OpenPGP é criada usando as chaves pública e privada decodificadas
	signer := CreateEntityFromKeys(pubkey, privKey)

	// A função `openpgp.ArmoredDetachSign` é usada para assinar o conteúdo presente na entrada padrão (os.Stdin) usando a chave privada contida na entidade signer.
	err := openpgp.ArmoredDetachSign(os.Stdout, signer, os.Stdin, nil)
	kingpin.FatalIfError(err, "Error signing input")
}

// VerifyFile  é responsável por verificar a assinatura de um arquivo usando uma chave pública OpenPGP.
func VerifyFile() {
	// Decodificar chave pública e assinatura
	pubKey := DecodePublicKey(*publicKey)
	sig := DecodeSignature(*signatureFile)

	// Objeto de hash é criado usando o algoritmo de hash especificado na assinatura `sig.Hash`. Os dados de entrada padrão (os.Stdin) são copiados para o objeto de hash usando a função io.Copy. Isso garante que o mesmo algoritmo de hash seja usado para verificar a assinatura.
	hash := sig.Hash.New()
	io.Copy(hash, os.Stdin)

	// Verificar a assinatura do dados de entrada usando a chave pública
	err := pubKey.VerifySignature(hash, sig)
	kingpin.FatalIfError(err, "Error signing input")
	kingpin.Errorf("Verified signature")
}

// CreateEntityFromKeys cria uma entidade OpenPGP a partir de uma chave pub/priv
func CreateEntityFromKeys(pubkey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	// Define as configurações da entidade
	config := packet.Config{
		DefaultHash:            crypto.SHA256,          // Algoritmo de hash padrão
		DefaultCipher:          packet.CipherAES256,    // Algoritmo de cifra padrão
		DefaultCompressionAlgo: packet.CompressionZLIB, // Algoritmo de compressão padrão
		CompressionConfig: &packet.CompressionConfig{
			Level: 9, // Nível de compressão
		},
		RSABits: *bits, //  Número de bits RSA
	}
	// Horário atual
	currenTime := config.Now()
	// Criar novo objeto de identidade (com campos vazios para nome, e-mail e comentário.)
	uid := packet.NewUserId("", "", "")

	// Criar uma entidade com a chave pública e privada
	e := openpgp.Entity{
		PrimaryKey: pubkey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity), // Armazenar as identidades associadas à entidade.
	}
	isPrimaryId := false

	// Uma identidade é adicionada à entidade e no mapa Identities
	e.Identities[uid.Id] = &openpgp.Identity{
		// A identidade inclui o nome, o objeto `uid`
		Name:   uid.Name,
		UserId: uid,
		// Assinatura própria
		SelfSignature: &packet.Signature{
			CreationTime: currenTime,                 // Horário de criação
			SigType:      packet.SigTypePositiveCert, // Tipo de assinatura
			PubKeyAlgo:   packet.PubKeyAlgoRSA,       // Algoritmo de chave pública
			Hash:         config.Hash(),              // Algorimo de hash
			IsPrimaryId:  &isPrimaryId,               // Não é uma identidade primária
			FlagsValid:   true,
			FlagSign:     true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	// Tempo de vida chave
	keyLifeTimeSecs := uint32(86400 * 365)

	// Subchave adicionada a entidade e
	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		// Inclui a chave pub/priv
		PublicKey:  pubkey,
		PrivateKey: privKey,
		// Assinatura associada a essa subchave
		Sig: &packet.Signature{
			CreationTime:              currenTime,
			SigType:                   packet.SigTypeSubkeyBinding, // Assinatura de subchave
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifeTimeSecs,
		},
	}
	// Retorna a entidade
	return &e
}

// GenerateKeys gerar o par de chaves pub/priv e salvá-las em arquivos
func GenerateKeys() {
	// Gerador de números aleatórios (rand.Reader) e o número de bits desejado para a chave (*bits).
	key, err := rsa.GenerateKey(rand.Reader, *bits)
	kingpin.FatalIfError(err, "Error generating RSA key: %s", err)

	// Arquivo criado para armazenar a chave privada
	priv, err := os.Create(filepath.Join(*keyOutputDir, *keyOutputPrefix+"privkey.gpg"))
	kingpin.FatalIfError(err, "Error writing private key to file: %s", err)
	// Garantir que o arquivo seja fechado ao final da execução
	defer priv.Close()

	// // Arquivo para armazenar a chave pública
	pub, err := os.Create(filepath.Join(*keyOutputDir, *keyOutputPrefix+"pubkey.gpg"))
	kingpin.FatalIfError(err, "Error writing public key to file: %s", err)
	// Garantir que o arquivo seja fechado ao final da execução
	defer pub.Close()

	// Escrever a chave privada e a chave pública nos respectivos arquivo
	EncodePrivateKey(priv, key)
	EncodePublicKey(pub, key)
}
