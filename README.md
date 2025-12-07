# bipkey

**bipkey** is a tool to generate and restore deterministic RSA/ECC private keys from high-entropy BIP-39 mnemonics. It was designed to be used for secure key creation and recovery for offline Certificate Authorities.

## The Goal:
Long-term private key storage for an offline Root CA is notoriously difficult. A cryptographic key must remain confidential, intact, and recoverable for decades, often outliving multiple hardware cycles, operating systems, personnel changes, and storage media formats. See the **Other Key Storage** section. Here's essentially the plan:


## How it works:

1) Generate a secure, high-entropy mnemonic using BIP39 on an airgapped and encrypted device.
2) Create a 256-bit BIP39 seed from the mnemonic and salt.
3) Use HKDF-SHA256 key derivation function to expand the 256-bit seed into about ~8KiB of randomness.
4) Use the HKDF-SHA256 output to seed a ChaCha20 stream as a DRBG for an arbitrary amount of data.
5) Use the DRBG as the source for generating the necessary parts of a private key:
   - Random scalars for use in ECC cryptography
   - Random large primes for use in RSA cryptography
6) Output the key and mnemonic. The key is deterministic and can be restored from the 24-word mnemonic and original seed.

## Supported Keys
Since this is targeted for Certificate Authorities, the keys supported are those which are conducive to creating signing certificates. This includes:

    Supported ECC curves:
     - P-256 (aliases: 256, p-256, p256, secp256r1, prime256v1)
     - P-384 (aliases: 384, p-384, p384, secp384r1, prime384v1)
     - P-521 (aliases: 521, p-521, p521, secp521r1, prime521v1)
     - Ed25519 (aliases: ed25519)

    Supported RSA sizes:
     - 2048
     - 3072
     - 4096
     - 8192

Some key types (P-521, Ed25519, RSA-8192) come with a warning: **\_\_\_\_\_\_\_ may have performance or compatibility implications. Ensure your environment supports it adequately.**

## Key Passwords:
You can optionally supply `--password/-p "<password>"` to encrypt the PKCS8 key. Note that this encryption is inherently non-deterministic. Encrypting the same key with the same password will result in different values for the final encrypted key, but the underlying key remains identical. This password is **only** used for PKCS8 encryption at rest and is not used during key derivation or generation. Therefore, unlike the mnemonic or salt, the PKCS8 password is not required to be used during key restoration.

## Key Generation:

    NAME:
       bipkey generate - Generate a new private key and mnemonic
    
    USAGE:
       bipkey generate [options]
    
    OPTIONS:
       --help, -h  show help
    
    GLOBAL OPTIONS:
       --verbose, -v                 Enable verbose logging output
       --salt string, -s string      (Recommended) optional salt value for key derivation
       --ecc string                  Generate an ECC private key with the specified curve (e.g. p256, p384, p521, ed25519)
       --rsa string                  Generate an RSA private key with the specified bit size (2048, 3072, 4096)
       --out string, -o string       Output file to save the generated key in PEM format.
       --password string, -p string  Optional password to encrypt the private key. Encryption is not deterministic, but the underlying key is.

**Example:**

    # bipkey generate -ecc 384 -salt "MyExampleSalt"
    Key Type: ECC
    Key Size: 384
    Key Salt: "MyExampleSalt"
    
    Mnemonic Words:
    01: toss     02: water    03: tilt     04: cable    05: radio    06: chronic  
    07: car      08: ethics   09: chronic  10: better   11: indoor   12: chat     
    13: code     14: carry    15: more     16: harbor   17: escape   18: pilot    
    19: panther  20: tooth    21: brave    22: cable    23: employ   24: blast    
    
    toss water tilt cable radio chronic car ethics chronic better indoor chat code carry more harbor escape pilot panther tooth brave cable employ blast
    
    Private Key (PEM):
    
    -----BEGIN PRIVATE KEY-----
    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDXV3uiN/6rAXE+zPbQ
    XLQ3fclUCjvbELo7dFSb6GWJRxjTvPA8RmwPJEnzy2x3mDOhZANiAATdBx/k5UeM
    7gLumPojD/S9Q//IN6O4MWV233dg3tZaC3OpIMspdcvwmmM5P736XeNz4hEy/7P3
    EnCw94MDww/ehqTIlCBCiKekkyQ8pf94Xndu8TqRN9XTuZJ844EEN8k=
    -----END PRIVATE KEY-----


## Key Restoration:
Restoring the key can be done using the mnemonic phrase and the original salt (if one was provided during generation). In accordance with BIP39, all words can be distinguished by their first 4 letters. Therefore, during restoration, only 4 letters for each word are required (or the complete word if it is less than 4 letters).

    NAME:
       bipkey restore - Restore a private key from an existing mnemonic
    
    USAGE:
       bipkey restore [options]
    
    OPTIONS:
       --mnemonic string, -m string  Existing 24-word mnemonic to restore the key from (first 4 letters minimum)
       --help, -h                    show help
    
    GLOBAL OPTIONS:
       --verbose, -v                 Enable verbose logging output
       --salt string, -s string      (Recommended) optional salt value for key derivation
       --ecc string                  Generate an ECC private key with the specified curve (e.g. p256, p384, p521, ed25519)
       --rsa string                  Generate an RSA private key with the specified bit size (2048, 3072, 4096)
       --out string, -o string       Output file to save the generated key in PEM format.
       --password string, -p string  Optional password to encrypt the private key. Encryption is not deterministic, but the underlying key is.

**Example:**

    # bipkey restore -ecc 384 -salt "MyExampleSalt"   
    Please enter your 24-word mnemonic recovery key in order (separated by spaces):
    TOSS WATE TILT CABL RADI CHRO CAR ETHI CHRO BETT INDO CHAT CODE CARR MORE HARB ESCA PILO PANT TOOT BRAV CABL EMPL BLAS
    
    Key Type: ECC
    Key Size: 384
    Key Salt: "MyExampleSalt"
    
    Mnemonic Words:
    01: toss     02: water    03: tilt     04: cable    05: radio    06: chronic  
    07: car      08: ethics   09: chronic  10: better   11: indoor   12: chat     
    13: code     14: carry    15: more     16: harbor   17: escape   18: pilot    
    19: panther  20: tooth    21: brave    22: cable    23: employ   24: blast    
    
    toss water tilt cable radio chronic car ethics chronic better indoor chat code carry more harbor escape pilot panther tooth brave cable employ blast
    
    Private Key (PEM):
    
    -----BEGIN PRIVATE KEY-----
    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDXV3uiN/6rAXE+zPbQ
    XLQ3fclUCjvbELo7dFSb6GWJRxjTvPA8RmwPJEnzy2x3mDOhZANiAATdBx/k5UeM
    7gLumPojD/S9Q//IN6O4MWV233dg3tZaC3OpIMspdcvwmmM5P736XeNz4hEy/7P3
    EnCw94MDww/ehqTIlCBCiKekkyQ8pf94Xndu8TqRN9XTuZJ844EEN8k=
    -----END PRIVATE KEY-----

## Encrypted Key Generation/Restoration

This example simply demonstrates generating and restoring a password-protected PKCS8 key file.

    ./bipkey generate -ecc 256 -p "MyPassword" -o key1_enc.pem
    ...
    creek alley ivory charge surface swallow grow valley swap cry machine bacon rain there purpose cycle poet popular glass episode cook brave cause safe
    ...
    -----BEGIN ENCRYPTED PRIVATE KEY-----
    MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAhgN6WWgGYMpQICJxAw
    DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEOOzVD9SmwpT9pRTcJGwHp4EgZAN
    kOg0cA50ss6V2BYqilWHXZvZS6liGiUzcMfH1bTc6wUKzQHN9sQafvs2JLpup7LU
    GL6TPfkXgqDIs+OLGEFIj3BMZHXKE95ahvaDjKM5iEKnsykpN6/IRxIMp9dk4KhL
    xeeNifmbMhYILsnktJGiUjm72/9pOdt59ITYp+yZ6O3qWGYm2xwk4j/trtqJaaM=
    -----END ENCRYPTED PRIVATE KEY-----

    ./bipkey restore -ecc 256 -p "MyPassword" -o key2_enc.pem -m "creek alley ivory charge surface swallow grow valley swap cry machine bacon rain there purpose cycle poet popular glass episode cook brave cause safe"
    ...
    -----BEGIN ENCRYPTED PRIVATE KEY-----
    MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgUtHLEWaTYbQICJxAw
    DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEIOqf2zyc3gVaARzL/AC4ZwEgZAi
    tHZflQDfwutHyPHD+/w6OWYsnD1PDlPnMrcRi9vYXNhpYa/InEXF9+jytN/KYR8z
    SLSfXCZZDrza7Q0gPPb0uRdvtqdw8xJT4Ti5hlQY+cJVZdkeVvkTCRNtUIky51c5
    rSJt88Fdt2/kYOk7j978rfEZCDHgj58qUA85TZtmdWz+6rhcXfU3v3Lmj2Op4I4=
    -----END ENCRYPTED PRIVATE KEY-----
   
Despite using the same password, the resulting ENCRYPTED PRIVATE KEY blocks are different. However, decrypting them with their respective passwords will result in the same keys:

    # openssl pkcs8 -in key1_enc.pem -out key1.pem -passin "pass:MyPassword"
    # openssl pkcs8 -in key2_enc.pem -out key2.pem -passin "pass:MyPassword"
    # sha256sum key1_enc.pem key2_enc.pem key1.pem key2.pem 
    2c77922b26921fbafcb3542a38749dac308fcf7a0ff19549f8f6a07f48db498c  key1_enc.pem
    ef3f4d3aea6762e76193c98bcf0f59820470a724c2510d403ef271d4e43b131e  key2_enc.pem
    ad9c5fbd5d799ab2fd28d69e7ecb522d7f08694ca72d75c395f1656535360325  key1.pem
    ad9c5fbd5d799ab2fd28d69e7ecb522d7f08694ca72d75c395f1656535360325  key2.pem


## Other Key Storage
#### USB Drive
Pros:
 - Cheap, ubiquitous, easy to use
 - Portable and easily stored

Failures:
 - High bit-rot rate over time (flash wear, charge leakage)
 - Possible filesystem corruption from improper ejection
 - Damage and data loss from static discharge, moisture, or heat
 - USB controllers can fail unpredictably
 - Malware/autorun infections if ever used on a compromised system

#### External Hard Drives
Pros:
 - Reasonable durability
 - Large capacity (oversied for this use-case)
 - Magnetic storage retains longer than flash storage

Failures:
 - Mechanical failures (bearings, heads, spindle, etc)
 - Suseptible to vibration and shock from drops
 - Magnetic degredation over long periods of time
 - Needs periodic powered maintenance to avoid stiction or bearing seizure

#### External Solid State Drives
Pros:
 - Faster and more mechanically tolerant compared to hard drives
 - No moving parts

Failures:
 - Retention loss from cell leakage over time when unpowered
 - SSD controller firmware bugs
 - High cost for cold storage over long periods of time

#### CD/DVD Optical Media
Pros:
 - Write-once, then read-only
 - Immune to EMP and magnetic fields
 - Physically fairly robust

Failures:
 - The coating compounds degrade over time, especially if organic
 - Scratches can cause fatal read errors
 - Inconsistent longevity which is generally shorter than the lifespan of the Root CA certificate

#### M-Drive Archival Optical Media
Pros:
 - Great lifespan, up to 1,000 years (at least claimed by marketing)
 - Inorganic recording layer
 - Resistant to light, heat, and humidity

Failures:
 - Expensive and slow to write
 - Requires specifically compatible optical drives which may not last
 - Suseptible to physical breakage and cracks
 - Real-world, science-backed research may not justify the 1,000 year claim

#### Printed/Handwritten Key
Pros:
 - Fully air-gapped
 - Immune to malware
 - As cheap as anything could be

Failures:
 - Fire or water damage
 - Ink fading over time
 - Human error during transcription
 - Paper becomes brittle over time

#### Hardware Security Modules (HSM)
Pros:
 - Strongest available protection for high-value keys
 - Anti-extraction guarantees
 - Tamper detection
 - Widely deployed and available
 - Can be deployed in clusters for higher tolerance

Failures:
 - High cost
 - Vendor lock-in
 - Firmware or hardware failure
 - Backup tokens or cards can wear out over time
 - If not properly replicated, a single hardware failure can lose the key