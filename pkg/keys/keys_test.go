package keys

import (
	"testing"

	"github.com/rs/zerolog"
)

const SALT = "bipkey-test-salt"
const PASSWORD = "bipkey-test-password"

type testKey struct {
	keyId               int
	mnemonic            Mnemonic
	expectedFingerprint string
}

func init() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestKeyGeneration(t *testing.T) {
	for _, keyType := range []ECCCurveID{ECCCurveP256, ECCCurveP384, ECCCurveP521, ECCCurveEd25519} {
		k1, err := GenerateKey(t.Context(), KeyTypeECC, int(keyType), SALT)
		if err != nil {
			t.Fatalf("failed to generate ECC key: %v", err)
		}
		if err := k1.Encrypt(PASSWORD); err != nil {
			t.Fatalf("failed to encrypt ECC key: %v", err)
		}
		if err := k1.Decrypt(PASSWORD); err != nil {
			t.Fatalf("failed to decrypt ECC key: %v", err)
		}
		fprint1 := k1.Fingerprint()

		k2, err := GenerateKeyFromMnemonic(t.Context(), KeyTypeECC, int(keyType), SALT, k1.mnemonic)
		if err != nil {
			t.Fatalf("failed to restore ECC key from mnemonic: %v", err)
		}
		if err := k2.Encrypt(PASSWORD); err != nil {
			t.Fatalf("failed to encrypt ECC key: %v", err)
		}
		if err := k2.Decrypt(PASSWORD); err != nil {
			t.Fatalf("failed to decrypt ECC key: %v", err)
		}
		fprint2 := k2.Fingerprint()

		if fprint1 != fprint2 {
			t.Fatalf("ECC key fingerprints do not match: %s != %s", fprint1, fprint2)
		}
	}

	for _, keyType := range []RSAKeyID{RSAKey2048, RSAKey3072, RSAKey4096, RSAKey8192} {
		k1, err := GenerateKey(t.Context(), KeyTypeRSA, int(keyType), SALT)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		if err := k1.Encrypt(PASSWORD); err != nil {
			t.Fatalf("failed to encrypt RSA key: %v", err)
		}
		if err := k1.Decrypt(PASSWORD); err != nil {
			t.Fatalf("failed to decrypt RSA key: %v", err)
		}
		fprint1 := k1.Fingerprint()

		k2, err := GenerateKeyFromMnemonic(t.Context(), KeyTypeRSA, int(keyType), SALT, k1.mnemonic)
		if err != nil {
			t.Fatalf("failed to restore RSA key from mnemonic: %v", err)
		}
		if err := k2.Encrypt(PASSWORD); err != nil {
			t.Fatalf("failed to encrypt RSA key: %v", err)
		}
		if err := k2.Decrypt(PASSWORD); err != nil {
			t.Fatalf("failed to decrypt RSA key: %v", err)
		}
		fprint2 := k2.Fingerprint()

		if fprint1 != fprint2 {
			t.Fatalf("RSA key fingerprints do not match: %s != %s", fprint1, fprint2)
		}
	}
}

func TestECCKeyRestoration(t *testing.T) {
	tests := []testKey{
		{
			keyId:               int(ECCCurveP256),
			mnemonic:            MustParseMnemonic("away mistake dance place sword title nurse diary skin soon figure sense force seat inform hedgehog debate around tortoise detail uncle situate draft wait"),
			expectedFingerprint: "43055375de9c2e3860c1ab135a93517f44ba1c51c58a4fa63f5373738d463957",
		},
		{
			keyId:               int(ECCCurveP384),
			mnemonic:            MustParseMnemonic("book ginger lyrics sing submit logic pluck main barely barrel tortoise saddle harsh peace cube cage basic name exact parade kitten fade trick state"),
			expectedFingerprint: "483298f6fec3e4c5ba311b6183cb23ceebfe9e4089a93235236d36bfde530e26",
		},
		{
			keyId:               int(ECCCurveP521),
			mnemonic:            MustParseMnemonic("aerobic pitch lesson lend october intact casual bronze disorder gossip lyrics virtual lounge lawsuit bachelor acoustic vehicle piece bridge pave sample maple expose marine"),
			expectedFingerprint: "56cbf02ae6ecfbdbb3155bdc3a7f1452b15a6a12d989cd9f40fad3a43c15358e",
		},
		{
			keyId:               int(ECCCurveEd25519),
			mnemonic:            MustParseMnemonic("sock extend arctic rare estate awake limit repair output tennis entry loyal female bean jacket grace drop whisper bridge search want lab token issue"),
			expectedFingerprint: "a04d97768e38421561684b48f902543e7a85d1189963903d7bb6df9e0024aaba",
		},
	}
	for _, test := range tests {
		key, err := GenerateKeyFromMnemonic(
			t.Context(),
			KeyTypeECC,
			test.keyId,
			SALT,
			test.mnemonic,
		)
		if err != nil {
			t.Fatalf("failed to generate ECC key from mnemonic: %v", err)
		}

		fingerprint1 := key.Fingerprint()

		if err := key.Encrypt(PASSWORD); err != nil {
			t.Fatalf("failed to encrypt ECC key: %v", err)
		}
		if err := key.Decrypt(PASSWORD); err != nil {
			t.Fatalf("failed to decrypt ECC key: %v", err)
		}

		fingerprint2 := key.Fingerprint()

		if fingerprint1 != fingerprint2 {
			t.Fatalf("ECC key fingerprints do not match after encrypt/decrypt: %s != %s", fingerprint1, fingerprint2)
		}

		if fingerprint1 != test.expectedFingerprint {
			t.Fatalf("unexpected ECC key fingerprint: got %s, want %s", fingerprint1, test.expectedFingerprint)
		}
	}
}

func TestRSAKeyRestoration(t *testing.T) {
	tests := []testKey{
		{
			keyId:               int(RSAKey2048),
			mnemonic:            MustParseMnemonic("worth ball broom life calm name foil fringe final average since traffic pig cook clap alert brush swallow rural glance guilt board vendor slight"),
			expectedFingerprint: "9351ddab1a122380da119ff25efd15a84ea56797740be2c1a60dac75edd42bb2",
		},
		{
			keyId:               int(RSAKey3072),
			mnemonic:            MustParseMnemonic("radar spoil crazy alien park lottery bitter return original burger upon fruit clarify magnet exist wheat sugar need donor allow ripple tuna cry scatter"),
			expectedFingerprint: "6c4efe263432292af4d4de9f9ef3d8e2b4c003ab50bbecb5b6be358384d6187f",
		},
		{
			keyId:               int(RSAKey4096),
			mnemonic:            MustParseMnemonic("kingdom marine vehicle senior cinnamon squeeze oxygen print home chest voyage service toward source glove host fit bench era bullet general kiss early math"),
			expectedFingerprint: "89033e95b464650780b269a7ebc2b601816119d52f6909c6fd2596ee648e3cef",
		},
		{
			keyId:               int(RSAKey8192),
			mnemonic:            MustParseMnemonic("rhythm fun flush habit genuine topple dune fire food chuckle rain shoulder describe digital idle movie upgrade nerve bicycle chuckle sport alien scan frost"),
			expectedFingerprint: "ecc797920f47adf1b043c8f304c41fa0684b184f2110aef7711794b95a531a52",
		},
	}

	for _, test := range tests {
		key, err := GenerateKeyFromMnemonic(
			t.Context(),
			KeyTypeRSA,
			test.keyId,
			SALT,
			test.mnemonic,
		)
		if err != nil {
			t.Fatalf("failed to generate RSA key from mnemonic: %v", err)
		}

		fingerprint1 := key.Fingerprint()

		if err := key.Encrypt(PASSWORD); err != nil {
			t.Fatalf("failed to encrypt RSA key: %v", err)
		}
		if err := key.Decrypt(PASSWORD); err != nil {
			t.Fatalf("failed to decrypt RSA key: %v", err)
		}

		fingerprint2 := key.Fingerprint()

		if fingerprint1 != fingerprint2 {
			t.Fatalf("RSA key fingerprints do not match after encrypt/decrypt: %s != %s", fingerprint1, fingerprint2)
		}

		if fingerprint1 != test.expectedFingerprint {
			t.Fatalf("unexpected RSA key fingerprint: got %s, want %s", fingerprint1, test.expectedFingerprint)
		}
	}
}
