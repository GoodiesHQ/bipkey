# bipkey

**bipkey** is a tool to generate and restore deterministic RSA/ECC private keys from high-entropy BIP-39 mnemonics. It was designed to be used for secure key creation and recovery for offline Certificate Authorities.

## The Goal:
Long-term private key storage for an offline Root CA is notoriously difficult. A cryptographic key must remain confidential, intact, and recoverable for decades, often outliving multiple hardware cycles, operating systems, personnel changes, and storage media formats. See the **Other Key Storage** section.

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

## Key Generation:

    NAME:
       bipkey generate - Generate a new private key and mnemonic
    
    USAGE:
       bipkey generate [options]
    
    OPTIONS:
       --help, -h  show help
    
    GLOBAL OPTIONS:
       --verbose, -v             Enable verbose logging output
       --salt string, -s string  (Recommended) optional salt value for key derivation
       --ecc string              Generate an ECC private key with the specified curve
       --rsa string              Generate an RSA private key with the specified bit size 
       --out string, -o string   Output file to save the generated key in PEM format.

**Example:**

    # bipkey generate --ecc 384 -salt "MyExampleSalt"
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
       --verbose, -v             Enable verbose logging output
       --salt string, -s string  (Recommended) optional salt value for key derivation
       --ecc string              Generate an ECC private key with the specified curve
       --rsa string              Generate an RSA private key with the specified bit size
       --out string, -o string   Output file to save the generated key in PEM format.

**Example:**

    # bipkey restore --ecc 384 -salt "MyExampleSalt"   
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