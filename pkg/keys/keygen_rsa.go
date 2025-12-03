package keys

import (
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

func generateRSA(r io.Reader, size int32) (*rsa.PrivateKey, error) {
	half := int(size / 2)
	p, err := derivePrime(r, half)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime p: %w", err)
	}

	q := p;
	for p.Cmp(q) == 0 {
		q, err = derivePrime(r, half)
		if err != nil {
			return nil, fmt.Errorf("failed to generate distinct prime q: %w", err)
		}
	}

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

func derivePrime(r io.Reader, bits int) (*big.Int, error) {
	byteLen := (bits + 7) / 8
	buf := make([]byte, byteLen)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes for prime: %w", err)
	}

	buf[0] |= 0x80         // ensure the number is of the desired bit length
	buf[byteLen-1] |= 0x01 // ensure the number is odd
	k := new(big.Int).SetBytes(buf)

	for {
		if k.ProbablyPrime(64) {
			return k, nil
		}
		// Increment and try again
		k.Add(k, big.NewInt(2))
	}
}
