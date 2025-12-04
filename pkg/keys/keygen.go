package keys

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
)

// GenerateKeyFromMnemonic generates a deterministic private key from the provided mnemonic and salt
func GenerateKeyFromMnemonic(ctx context.Context, keyType KeyType, keyId int, salt string, mnemonic Mnemonic) (*Key, error) {
	saltBytes := []byte(salt)

	mnemonic, err := mnemonic.Normalize()
	if err != nil {
		return nil, fmt.Errorf("failed to normalize mnemonic: %w", err)
	}
	log.Debug().Msg("Normalized mnemonic for key generation.")

	// derive seed from mnemonic and salt
	seed := bip39.NewSeed(mnemonic.String(), salt)
	log.Debug().Msg("Derived seed from mnemonic and salt.")

	// use HKDF to derive the private key from the BIP39 seed and salt
	kdf := hkdf.New(sha256.New, seed, saltBytes, nil)
	log.Debug().Msg("Initialized HKDF-SHA256 using BIP39 seed + salt for key derivation.")

	var privKey crypto.PrivateKey

	switch keyType {
	case KeyTypeECC:
		privKey, err = generateECC(kdf, ECCCurveID(keyId))
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECC key: %w", err)
		}
	case KeyTypeRSA:
		privKey, err = generateRSA(kdf, RSAKeyID(keyId))
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
	log.Debug().Msg("Marshalled private key to PKCS8 key format.")

	return &Key{
		keyType:    keyType,
		keyId:      keyId,
		salt:       salt,
		PrivateKey: privKey,
		Der:        der,
		mnemonic:   mnemonic,
	}, nil
}

// GenerateKey generates a new deterministic private key and mnemonic
func GenerateKey(ctx context.Context, keyType KeyType, keyId int, salt string) (*Key, error) {
	mnemonic, err := GenerateMnemonic(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}
	log.Debug().Msg("Created a new mnemonic for key generation.")

	return GenerateKeyFromMnemonic(ctx, keyType, keyId, salt, *mnemonic)
}
