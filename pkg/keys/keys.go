package keys

import (
	"crypto"
	"crypto/sha256"
	"encoding/pem"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/tyler-smith/go-bip39"
)

type KeyType string

const (
	KeyTypeNone KeyType = ""
	KeyTypeECC  KeyType = "ECC"
	KeyTypeRSA  KeyType = "RSA"
)

type Key struct {
	keyType    KeyType
	keyId      int
	salt       string
	PrivateKey crypto.PrivateKey
	Der        []byte
	mnemonic   Mnemonic
}

var longestWordLen int
var formatWord string

func init() {
	for _, word := range bip39.GetWordList() {
		if len(word) > longestWordLen {
			longestWordLen = len(word)
		}
	}

	formatWord = fmt.Sprintf("%%02d: %%-%ds", longestWordLen+1)
}

func (k Key) PEM() string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: k.Der,
	}))
}

func (k Key) Fingerprint() string {
	pem := k.PEM()
	h := sha256.New()
	_, err := h.Write([]byte(pem))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (k *Key) Display() {
	const cols = 6

	// Display key information
	fmt.Printf("Key Type: %s\n", k.keyType)
	var keySize int
	switch k.keyType {
	case KeyTypeECC:
		keySize = getSizeECC(ECCCurveID(k.keyId))
	case KeyTypeRSA:
		keySize = getSizeRSA(RSAKeyID(k.keyId))
	}

	fmt.Printf("Key Size: %d\n", keySize)
	if k.salt == "" {
		fmt.Printf("Key Salt: (none)\n")
	} else {
		fmt.Printf("Key Salt: \"%s\"\n", k.salt)
	}

	fmt.Println("\nMnemonic Words:")
	for i, word := range k.mnemonic {
		fmt.Printf(formatWord, i+1, word)
		if i%cols == cols-1 {
			fmt.Println()
		}
	}
	fmt.Println()
	fmt.Println(k.mnemonic.String())

	fmt.Println("\nPrivate Key (PEM):")
	fmt.Println()

	log.Debug().Str("fingerprint", k.Fingerprint()).Msg("Generated key fingerprint.")
	fmt.Println(k.PEM())
}
