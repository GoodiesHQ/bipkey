package keys

import (
	"crypto/cipher"
	"io"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/chacha20"
)

type StreamChaCha20 struct {
	stream cipher.Stream // underlying cipher stream
	zbuf   []byte        // zero-byte buffer for XORKeyStream
}

// Read implements io.Reader by generating keystream bytes xor-ed with zero-byte buffer
func (s *StreamChaCha20) Read(dst []byte) (int, error) {
	totalSize := len(dst)
	if totalSize == 0 {
		return 0, nil
	}
	if totalSize == 1 {
		// ignore MaybeReadByte requests for a single byte
		return 1, nil
	}

	// n = number of remaining bytes to read
	n := totalSize

	for n > 0 {
		chunkSize := n
		if chunkSize > len(s.zbuf) {
			chunkSize = len(s.zbuf)
		}
		s.stream.XORKeyStream(dst[:chunkSize], s.zbuf[:chunkSize])
		dst = dst[chunkSize:]
		n -= chunkSize
	}
	return totalSize, nil
}

func NewStreamChaCha20(r io.Reader) (*StreamChaCha20, error) {
	key := make([]byte, chacha20.KeySize)
	nonce := make([]byte, chacha20.NonceSizeX)

	// read key and nonce from the provided reader
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	log.Debug().Msg("Generated key and nonce for ChaCha20 stream cipher.")

	// initialize ChaCha20 stream cipher
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	log.Debug().Msg("Initialized ChaCha20 stream cipher.")

	return &StreamChaCha20{
		stream: stream,
		zbuf:   make([]byte, 4096),
	}, nil
}
