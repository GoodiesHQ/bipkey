package keys

import (
	// "crypto/ecdh"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
	"strings"
)

type ECCCurveID int

const (
	ECCCurveNone ECCCurveID = iota
	ECCCurveP256
	ECCCurveP384
	ECCCurveP521
	ECCCurveEd25519
)

func getSizeECC(id ECCCurveID) int {
	switch id {
	case ECCCurveP256:
		return 256
	case ECCCurveP384:
		return 384
	case ECCCurveP521:
		return 521
	case ECCCurveEd25519:
		return 256
	}
	return 0
}

// eccCurveInfo holds information and aliases about supported ECC curves
type eccCurveInfo struct {
	ID      ECCCurveID // associated ECCCurveID
	Name    string     // canonical name
	Aliases []string   // all accepted user inputs (lowercase)
}

var supportedECCCurves = []eccCurveInfo{
	{
		ID:      ECCCurveP256,
		Name:    "P-256",
		Aliases: []string{"256", "p-256", "p256", "secp256r1", "prime256v1"},
	},
	{
		ID:      ECCCurveP384,
		Name:    "P-384",
		Aliases: []string{"384", "p-384", "p384", "secp384r1", "prime384v1"},
	},
	{
		ID:      ECCCurveP521,
		Name:    "P-521",
		Aliases: []string{"521", "p-521", "p521", "secp521r1", "prime521v1"},
	},
	{
		ID:      ECCCurveEd25519,
		Name:    "Ed25519",
		Aliases: []string{"ed25519"},
	},
}

var eccAliases map[string]eccCurveInfo

func init() {
	eccAliases = make(map[string]eccCurveInfo)
	for _, info := range supportedECCCurves {
		for _, alias := range info.Aliases {
			eccAliases[strings.ToLower(alias)] = info
		}
	}
}

// SupportedECC returns a string listing supported ECC curves and their aliases
func SupportedECC() string {
	var builder strings.Builder
	builder.WriteString("Supported ECC curves:\n")
	for _, info := range supportedECCCurves {
		builder.WriteString(fmt.Sprintf(" - %s (aliases: %s)\n", info.Name, strings.Join(info.Aliases, ", ")))
	}
	return builder.String()
}

// ParseECCCurve parses the given string to determine the ECCCurveID
func ParseECCCurve(val string) (ECCCurveID, error) {
	val = strings.ToLower(strings.TrimSpace(val))
	if val == "" {
		return ECCCurveNone, nil
	}

	if info, ok := eccAliases[val]; ok {
		return info.ID, nil
	}

	return ECCCurveNone, fmt.Errorf("unsupported ECC curve: %s", val)
}

// generateEdECC generate an edwards curve ECC key
func generateEdECC(r io.Reader, id ECCCurveID) (crypto.PrivateKey, error) {
	switch id {
	case ECCCurveEd25519:
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(r, seed); err != nil {
			return nil, fmt.Errorf("failed to read seed for Ed25519 key: %w", err)
		}

		priv := ed25519.NewKeyFromSeed(seed)
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported ECC curve")
	}
}

// generateNistECC generates a NIST curve ECC key
func generateNistECC(r io.Reader, id ECCCurveID) (crypto.PrivateKey, error) {
	var ecdsaCurve elliptic.Curve

	switch id {
	case ECCCurveP256:
		ecdsaCurve = elliptic.P256()
	case ECCCurveP384:
		ecdsaCurve = elliptic.P384()
	case ECCCurveP521:
		ecdsaCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ECC curve")
	}

	// Read the number of bytes needed for the curve's scalar, with extra bytes to reduce bias
	params := ecdsaCurve.Params()
	scalarSize := (params.N.BitLen() + 7) / 8           // bytes needed for scalar
	scalarSizeWide := (params.N.BitLen() + 128 + 7) / 8 // add 128 bits to reduce bias

	d, err := generateScalarWide(r, params.N, scalarSizeWide)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scalar: %w", err)
	}

	// Convert to ECDH private key first
	scalarBytes := make([]byte, scalarSize)
	d.FillBytes(scalarBytes)

	// Convert to ecdsa.PrivateKey for compatibility
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: ecdsaCurve,
		},
		D: d,
	}

	priv.X, priv.Y = ecdsaCurve.ScalarBaseMult(scalarBytes)

	return priv, nil
}

// generateECC generates an ECC private key of the specified size using the provided reader for randomness.
func generateECC(r io.Reader, id ECCCurveID) (crypto.PrivateKey, error) {
	switch id {
	case ECCCurveP256, ECCCurveP384, ECCCurveP521:
		return generateNistECC(r, id)
	case ECCCurveEd25519:
		return generateEdECC(r, id)
	default:
		return nil, fmt.Errorf("unsupported ECC curve")
	}
}

// generateScalarWidw generates a scalar in [1, n-1] using wide byte input to reduce bias
func generateScalarWide(r io.Reader, n *big.Int, byteLen int) (*big.Int, error) {
	buf := make([]byte, byteLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(buf)

	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(n, one)
	k.Mod(k, nMinus1)
	k.Add(k, one)
	return k, nil
}
