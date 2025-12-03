package keys

import (
	// "crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
)

// generateECC generates an ECC private key of the specified size using the provided reader for randomness.
func generateECC(r io.Reader, size int32) (*ecdsa.PrivateKey, error) {
	var ecdsaCurve elliptic.Curve

	switch size {
	case 256:
		ecdsaCurve = elliptic.P256()
	case 384:
		ecdsaCurve = elliptic.P384()
	case 521:
		ecdsaCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ECC curve size: %d", size)
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

// generateScalar generates a scalar in [1, n-1]
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