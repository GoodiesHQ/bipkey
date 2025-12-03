package keys

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
)

// GenerateKeyFromMnemonic generates a deterministic private key from the provided mnemonic and salt
func GenerateKeyFromMnemonic(ctx context.Context, keyType KeyType, size int32, salt string, mnemonic Mnemonic) (*Key, error) {
	saltBytes := []byte(salt)

	mnemonic, err := mnemonic.Normalize()
	if err != nil {
		return nil, fmt.Errorf("failed to normalize mnemonic: %w", err)
	}

	// derive seed from mnemonic and salt
	seed := bip39.NewSeed(mnemonic.String(), salt)

	// use HKDF to derive the private key from the BIP39 seed and salt
	kdf := hkdf.New(sha256.New, seed, saltBytes, nil)

	var privKey crypto.PrivateKey

	switch keyType {
	case KeyTypeECC:
		privKey, err = generateECC(kdf, size)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECC key: %w", err)
		}
	case KeyTypeRSA:
		privKey, err = generateRSA(kdf, size)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECC key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// marshal private key to DER format
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
	}

	return &Key{
		keyType:    keyType,
		keySize:    size,
		salt:       salt,
		PrivateKey: privKey,
		Der:        der,
		mnemonic:   mnemonic,
	}, nil
}

// GenerateKey generates a new deterministic private key and mnemonic
func GenerateKey(ctx context.Context, keyType KeyType, size int32, salt string) (*Key, error) {
	mnemonic, err := GenerateMnemonic(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// convert any short words to full words
	mnemonicNormalized, err := mnemonic.Normalize()
	if err != nil {
		return nil, fmt.Errorf("failed to normalize mnemonic: %w", err)
	}

	return GenerateKeyFromMnemonic(ctx, keyType, size, salt, mnemonicNormalized)
}
