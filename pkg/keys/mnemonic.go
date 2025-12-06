package keys

import (
	"context"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

const MNEMONIC_WORD_COUNT = 24
const MNEMONIC_ENTROPY_BITS = 256

type Mnemonic [MNEMONIC_WORD_COUNT]string

// String returns the mnemonic as a space-delimited string
func (m Mnemonic) String() string {
	return strings.Join(m[:], " ")
}

// Normalize returns a normalized version of the mnemonic with the complete words
func (m Mnemonic) Normalize() (Mnemonic, error) {
	var normalized Mnemonic
	for i, word := range m {
		_, wordFull, err := GetWordIndex(word)
		if err != nil {
			return m, err
		}
		normalized[i] = wordFull
	}
	return normalized, nil
}

// MnemonicShort returns the mnemonic words uppercase truncated to their first 4 letters.
func (m *Mnemonic) Short() Mnemonic {
	var short Mnemonic

	for i, word := range m {
		if len(word) > 4 {
			word = word[:4]
		}
		short[i] = strings.ToUpper(word)
	}

	return short
}

// GenerateMnemonic generates a new, random BIP-39 mnemonic with 24 words.
func GenerateMnemonic(ctx context.Context) (*Mnemonic, error) {
	entropy, err := bip39.NewEntropy(MNEMONIC_ENTROPY_BITS)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy for mnemonic generation: %w", err)
	}
	mnemonicString, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	var m Mnemonic
	for i, word := range strings.Fields(strings.TrimSpace(mnemonicString)) {
		m[i] = word
	}

	m, err = m.Normalize()
	if err != nil {
		return nil, fmt.Errorf("failed to normalize mnemonic: %w", err)
	}

	return &m, nil
}

var bip39Words []string

func init() {
	bip39Words = bip39.GetWordList()
}

func MustParseMnemonic(mnemonicString string) Mnemonic {
	mnemonic, err := ParseMnemonic(mnemonicString)
	if err != nil {
		panic(err)
	}
	return mnemonic
}

func ParseMnemonic(mnemonicString string) (Mnemonic, error) {
	words := strings.Fields(strings.TrimSpace(mnemonicString))
	if len(words) != MNEMONIC_WORD_COUNT {
		return Mnemonic{}, fmt.Errorf("mnemonic must have %d words, found %d", MNEMONIC_WORD_COUNT, len(words))
	}

	var mnemonic Mnemonic
	for i, word := range words {
		_, wordFull, err := GetWordIndex(word)
		if err != nil {
			return Mnemonic{}, fmt.Errorf("invalid mnemonic word '%s': %w", word, err)
		}
		mnemonic[i] = wordFull
	}
	return mnemonic, nil
}

// GetWordIndex returns the index and full word from the BIP-39 word list for the given word or its 4-letter prefix.
func GetWordIndex(word string) (int, string, error) {
	originalWord := word

	if len(word) > 4 {
		word = word[:4]
	}
	word = strings.ToLower(word)

	for i, w := range bip39Words {
		if len(word) < 4 {
			if word == w {
				return i, w, nil
			}
		} else {
			if strings.HasPrefix(w, strings.ToLower(word)) {
				return i, w, nil
			}
		}
	}

	return -1, "", fmt.Errorf("word '%s' not found in BIP-39 word list", originalWord)
}
