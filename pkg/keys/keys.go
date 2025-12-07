package keys

import (
	"crypto"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"reflect"

	"github.com/rs/zerolog/log"
	"github.com/tyler-smith/go-bip39"
	"github.com/youmark/pkcs8"
)

type KeyType string

const (
	KeyTypeNone KeyType = ""
	KeyTypeECC  KeyType = "ECC"
	KeyTypeRSA  KeyType = "RSA"
)

type Key struct {
	encrypted  bool
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

// Encrypt encrypts the private key using the provided password
func (k *Key) Encrypt(password string) error {
	if k.encrypted {
		return fmt.Errorf("key is already encrypted")
	}

	// marshal and encrypt private key to DER format
	der, err := pkcs8.MarshalPrivateKey(k.PrivateKey, []byte(password), pkcs8.DefaultOpts)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	k.Der = der
	k.encrypted = true
	return nil
}

func (k *Key) Decrypt(password string) error {
	if !k.encrypted {
		return fmt.Errorf("key is not encrypted")
	}

	// decrypt and unmarshal private key from DER format
	privKey, err := pkcs8.ParsePKCS8PrivateKey(k.Der, []byte(password))
	if err != nil {
		return fmt.Errorf("failed to decrypt private key: %w", err)
	}

	if reflect.TypeOf(privKey) != reflect.TypeOf(k.PrivateKey) {
		return fmt.Errorf("decrypted key type does not match original key type")
	}

	if !reflect.DeepEqual(privKey, k.PrivateKey) {
		return fmt.Errorf("decrypted key does not match original key")
	}

	k.Der, err = pkcs8.MarshalPrivateKey(privKey, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	k.encrypted = false
	return nil
}

// PEM returns the PEM-encoded representation of the private key
func (k Key) PEM() string {
	var t string
	if k.encrypted {
		t = "ENCRYPTED PRIVATE KEY"
	} else {
		t = "PRIVATE KEY"
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  t,
		Bytes: k.Der,
	}))
}

// Fingerprint returns the SHA-256 fingerprint of the PEM-encoded private key
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
