package keys

import (
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const PRIMALITY_TESTS = 256

type RSAKeyID int

const (
	RSAKeyNone RSAKeyID = iota
	RSAKey2048
	RSAKey3072
	RSAKey4096
	RSAKey8192
)

func getSizeRSA(id RSAKeyID) int {
	switch id {
	case RSAKey2048:
		return 2048
	case RSAKey3072:
		return 3072
	case RSAKey4096:
		return 4096
	case RSAKey8192:
		return 8192
	}
	return 0
}

// SupportedRSA returns a string listing supported RSA key sizes
func SupportedRSA() string {
	var builder strings.Builder
	builder.WriteString("Supported RSA sizes:\n")
	builder.WriteString(fmt.Sprintf(" - %d\n", getSizeRSA(RSAKey2048)))
	builder.WriteString(fmt.Sprintf(" - %d\n", getSizeRSA(RSAKey3072)))
	builder.WriteString(fmt.Sprintf(" - %d\n", getSizeRSA(RSAKey4096)))
	builder.WriteString(fmt.Sprintf(" - %d\n", getSizeRSA(RSAKey8192)))
	return builder.String()
}

// ParseRSAKeyID parses the given string to determine the RSAKeyID
func ParseRSAKeyID(val string) (RSAKeyID, error) {
	val = strings.ToLower(strings.TrimSpace(val))
	if val == "" {
		return RSAKeyNone, nil
	}

	switch val {
	case "2048":
		return RSAKey2048, nil
	case "3072":
		return RSAKey3072, nil
	case "4096":
		return RSAKey4096, nil
	case "8192":
		return RSAKey8192, nil
	default:
		return RSAKeyNone, fmt.Errorf("unsupported RSA key size")
	}
}

// generateRSA generates an RSA private key using the provided reader for randomness
func generateRSA(r io.Reader, id RSAKeyID) (*rsa.PrivateKey, error) {
	var size = getSizeRSA(id)
	if size == 0 {
		return nil, fmt.Errorf("unsupported RSA key size")
	}

	// using rsa.GenerateKey is not guaranteed to be deterministic across future Go versions
	// so we implement our own key generation using the provided reader
	half := int(size / 2)
	p, err := derivePrime(r, half)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime p: %w", err)
	}

	q := p
	// ensure p and q are distinct primes
	for p.Cmp(q) == 0 {
		q, err = derivePrime(r, half)
		if err != nil {
			return nil, fmt.Errorf("failed to generate distinct prime q: %w", err)
		}
	}

	// compute RSA private key components
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)
	e := big.NewInt(65537) // common public exponent
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, fmt.Errorf("failed to compute modular inverse")
	}

	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RSA key: %w", err)
	}
	return priv, nil
}

// derivePrime creates a prime number of the specified bit length from the provided reader
func derivePrime(r io.Reader, bits int) (*big.Int, error) {
	byteLen := (bits + 7) / 8
	buf := make([]byte, byteLen)

	// only read once from r to minimize calls to the reader, preserve limited HKDF entropy
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes for prime: %w", err)
	}

	buf[0] |= 0x80         // ensure the number is of the desired bit length
	buf[byteLen-1] |= 0x01 // ensure the number is odd
	k := new(big.Int).SetBytes(buf)

	two := big.NewInt(2)
	for {
		// test for primality
		if k.ProbablyPrime(PRIMALITY_TESTS) {
			return k, nil
		}

		// Increment and try again
		k.Add(k, two)
	}
}
