# sealed-messages Specification

## Purpose
Define authenticated AES-GCM key generation, sealed-message encoding, and field extraction.
## Requirements
### Requirement: Generate a secret key

`aes.generateKey()` SHALL return a non-extractable AES-256-GCM CryptoKey with encrypt and decrypt usages. The `extractable` option SHALL accept only booleans.

#### Scenario: Default key

- **WHEN** the caller generates a key without options
- **THEN** sealing and opening succeed and raw export fails

#### Scenario: Explicit export

- **WHEN** the caller sets `extractable: true`
- **THEN** Web Crypto can export 32 key bytes

#### Scenario: Invalid option

- **WHEN** the caller supplies the string `false` as the option value
- **THEN** generation rejects

### Requirement: Seal and open text

`aes.seal(key, text)` SHALL encode well-formed text as UTF-8 and choose a new random 12-byte nonce on each invocation. `aes.open(key, message)` SHALL authenticate before returning text.

#### Scenario: Text boundaries

- **WHEN** a caller seals empty text, Unicode text with a leading BOM, or a long string
- **THEN** opening with the same key returns the original text

#### Scenario: Invalid inputs

- **WHEN** a caller supplies a password in place of a CryptoKey, a key of the wrong algorithm or size, non-string plaintext, or an unpaired surrogate
- **THEN** the operation rejects

#### Scenario: Authentication failure

- **WHEN** the key differs or any nonce, ciphertext or tag byte is changed
- **THEN** opening rejects

### Requirement: Version 1 wire format

The envelope SHALL be `sfet1.` followed by canonical standard Base64 of nonce, ciphertext and 16-byte tag in that order. GCM additional authenticated data SHALL be the UTF-8 bytes of `sfet1`.

#### Scenario: Independent reader

- **WHEN** another implementation supplies the same key, nonce, ciphertext, tag and additional authenticated data
- **THEN** authenticated decryption yields the original UTF-8 bytes

#### Scenario: Invalid envelope

- **WHEN** the prefix is unknown, Base64 is invalid or noncanonical, or the decoded payload is shorter than 28 bytes
- **THEN** opening and field extraction reject the envelope

### Requirement: Read fields without a key

`aes.extractIv`, `aes.extractCiphertext` and `aes.extractTag` SHALL synchronously return the corresponding bytes as Uint8Array values without authenticating or decrypting them.

#### Scenario: Empty plaintext

- **WHEN** a caller extracts the fields of a sealed empty string
- **THEN** the field lengths are 12, 0 and 16 bytes respectively

#### Scenario: Modified but well-formed payload

- **WHEN** a caller extracts a changed tag
- **THEN** the helper returns the stored bytes and authenticated opening fails

