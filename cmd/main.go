package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/goodieshq/bipkey/pkg/keys"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

var app *cli.Command

// initialize logging and the CLI application with commands and flags
func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	}).Level(zerolog.InfoLevel)

	app = &cli.Command{
		Name:        "bipkey",
		Usage:       "Generate and restore RSA/ECC private keys from BIP-39 mnemonics",
		Description: "bipkey is a tool to generate and restore deterministic RSA/ECC private keys from BIP-39 mnemonics. Used for secure key backup and recovery for offline Certificate Authorities.",
		UsageText:   "bipkey [-ecc <curve> | -rsa <key size>] [-salt <salt value>] [generate/restore]",
		Commands: []*cli.Command{
			{
				Name:   "generate",
				Usage:  "Generate a new private key and mnemonic",
				Action: actionGenerate,
			},
			{
				Name:   "restore",
				Usage:  "Restore a private key from an existing mnemonic",
				Action: actionRestore,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "mnemonic",
						Aliases: []string{"m"},
						Usage:   "Existing 24-word mnemonic to restore the key from (first 4 letters minimum)",
						Value:   "",
					},
				},
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Usage:   "Enable verbose logging output",
				Aliases: []string{"v"},
			},
			&cli.StringFlag{
				Name:  "salt",
				Usage: "Required salt value for key derivation",
				Value: "",
				Validator: func(val string) error {
					if val == "" {
						return cli.Exit("Salt value cannot be empty.", 1)
					}
					if len(val) < 12 {
						log.Warn().Msg("It's recommended to use a salt value of at least 12 characters for better security.")
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:  "ecc",
				Usage: "Generate an ECC private key with the specified curve bit size (256, 384, 521)",
				Value: "",
				Validator: func(val string) error {
					id, err := keys.ParseECCCurve(val)
					if err != nil {
						fmt.Printf("%s\n", keys.SupportedECC())
						return cli.Exit(err.Error(), 1)
					}

					switch id {
					case keys.ECCCurveP256:
						log.Debug().Msg("Using P-256 curve for ECC key generation.")
					case keys.ECCCurveP384:
						log.Debug().Msg("Using P-384 curve for ECC key generation.")
					case keys.ECCCurveP521:
						log.Debug().Msg("Using P-521 curve for ECC key generation.")
						log.Warn().Msg("Using P-521 curve may have performance or compatibility implications. Ensure your environment supports it adequately.")
					case keys.ECCCurveEd25519:
						log.Debug().Msg("Using Ed25519 curve for ECC key generation.")
						log.Warn().Msg("Using Ed25519 curve may have performance or compatibility implications. Ensure your environment supports it adequately.")
					default:
						return cli.Exit("unsupported ECC curve", 1)
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:  "rsa",
				Usage: "Generate an RSA private key with the specified bit size (2048, 3072, 4096)",
				Value: "",
				Validator: func(val string) error {
					id, err := keys.ParseRSAKeyID(val)
					if err != nil {
						fmt.Printf("%s\n", keys.SupportedRSA())
						return cli.Exit(err.Error(), 1)
					}

					switch id {
					case keys.RSAKey2048:
						log.Debug().Msg("Using 2048-bit RSA key size for generation.")
					case keys.RSAKey3072:
						log.Debug().Msg("Using 3072-bit RSA key size for generation.")
					case keys.RSAKey4096:
						log.Debug().Msg("Using 4096-bit RSA key size for generation.")
					case keys.RSAKey8192:
						log.Debug().Msg("Using 8192-bit RSA key size for generation.")
						log.Warn().Msg("Using RSA-8192 may have performance or compatibility implications. Ensure your environment supports it adequately.")
					default:
						return cli.Exit("unsupported RSA key size", 1)
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:    "out",
				Aliases: []string{"o"},
				Usage:   "Output file to save the generated key in PEM format.",
				Value:   "",
			},
		},
	}
}

func main() {
	// create a context that listens for OS signals to gracefully handle termination
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, os.Args); err != nil {
		if err == context.Canceled {
			return
		}
		// log.Fatal().Err(err).Msg("Application error")
	}
}

func setLogging(c *cli.Command) {
	if c.Bool("verbose") {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}
}

// writeFile writes the provided data to the specified output file
func writeFile(c *cli.Command, data string) error {
	// If no output file is specified, return early
	outFile := c.String("out")
	if outFile == "" {
		return nil
	}

	// Create the output file, ensuring any existing file is overwritten
	f, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	// Write the data to the file
	_, err = f.WriteString(data)
	if err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}

	return nil
}

// getKeyInfo retrieves the key type, size, and salt from the command flags
func getKeyInfo(c *cli.Command) (keys.KeyType, int, string, error) {
	eccOpt := c.String("ecc")
	rsaOpt := c.String("rsa")
	salt := c.String("salt")

	// key info defaults
	keyType := keys.KeyTypeNone
	keyId := 0

	// RSA or ECC must be specified
	if eccOpt == "" && rsaOpt == "" {
		return keys.KeyTypeNone, 0, "", cli.Exit("At least one of -ecc or -rsa flags must be specified.", 1)
	}

	// both ECC and RSA cannot be specified
	if eccOpt != "" && rsaOpt != "" {
		return keys.KeyTypeNone, 0, "", cli.Exit("Only one of -ecc or -rsa flags may be specified.", 1)
	}

	if eccOpt != "" {
		// use ECC key type
		keyType = keys.KeyTypeECC
		eccId, err := keys.ParseECCCurve(eccOpt)
		if err != nil {
			return keys.KeyTypeNone, 0, "", cli.Exit(err.Error(), 1)
		}
		keyId = int(eccId)
	}

	if rsaOpt != "" {
		// use RSA key type
		keyType = keys.KeyTypeRSA
		rsaId, err := keys.ParseRSAKeyID(rsaOpt)
		if err != nil {
			return keys.KeyTypeNone, 0, "", cli.Exit(err.Error(), 1)
		}
		keyId = int(rsaId)
	}

	// validate key type and size
	if keyType == keys.KeyTypeNone {
		return keys.KeyTypeNone, 0, "", cli.Exit("Invalid key type specified.", 1)
	}

	// salt is not required but is recommended
	if len(salt) == 0 {
		log.Warn().Msg("Salt value is not provided. It's recommended to use a salt value for better security.")
	}

	return keyType, keyId, salt, nil
}

// actionGenerate generates a new private key and mnemonic based on the provided command flags
func actionGenerate(ctx context.Context, c *cli.Command) error {
	setLogging(c)
	keyType, keyId, salt, err := getKeyInfo(c)
	if err != nil {
		return err
	}

	k, err := keys.GenerateKey(ctx, keyType, keyId, salt)
	if err != nil {
		return err
	}
	k.Display()
	if err := writeFile(c, k.PEM()); err != nil {
		log.Error().Err(err).Msg("Failed to write key to file")
	}

	return nil
}

// promptMnemonic prompts the user to enter their 24-word mnemonic recovery key
func promptMnemonic() (string, error) {
	fmt.Println("Please enter your 24-word mnemonic recovery key in order (separated by spaces):")
	var mnemonicString string

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read mnemonic input: %w", err)
	}
	fmt.Println()

	mnemonicString = strings.TrimSpace(line)
	return mnemonicString, nil
}

// actionRestore restores a private key from an existing mnemonic/salt
func actionRestore(ctx context.Context, c *cli.Command) error {
	setLogging(c)
	keyType, keySize, salt, err := getKeyInfo(c)
	if err != nil {
		return err
	}

	var mnemonic keys.Mnemonic

	mnemonicString := c.String("mnemonic")
	if mnemonicString == "" {
		mnemonicString, err = promptMnemonic()
		if err != nil {
			return err
		}

	}

	mnemonicWords := strings.Split(mnemonicString, " ")
	if len(mnemonicWords) != keys.MNEMONIC_WORD_COUNT {
		return cli.Exit(fmt.Sprintf("Invalid mnemonic: expected %d words, got %d", keys.MNEMONIC_WORD_COUNT, len(mnemonicWords)), 1)
	}

	copy(mnemonic[:], mnemonicWords)

	k, err := keys.GenerateKeyFromMnemonic(ctx, keyType, keySize, salt, mnemonic)
	if err != nil {
		return err
	}

	k.Display()
	if err := writeFile(c, k.PEM()); err != nil {
		log.Error().Err(err).Msg("Failed to write key to file")
	}

	return nil
}
