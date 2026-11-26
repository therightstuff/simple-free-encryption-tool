## ADDED Requirements

### Requirement: Explicit CBC encryption and legacy recovery

CBC encryption SHALL require an explicit IV. A legacy decrypt call that uses the historical fallback SHALL use the UTF-8 bytes of sixteen ASCII zero digits and warn on every such call that ciphertext security is not guaranteed. Warnings SHALL omit keys and message data.

#### Scenario: Missing encryption IV

- **WHEN** an IV is omitted, null or empty
- **THEN** encryption rejects

#### Scenario: Historical ciphertext

- **WHEN** a caller omits the IV when reading a record written with the old fallback
- **THEN** the record decrypts and a warning is logged

#### Scenario: Explicit IV

- **WHEN** a caller decrypts with the original explicit IV
- **THEN** the legacy warning is silent

### Requirement: Parameter generation and compatibility

`cbc.generateIv()` and `gcm.generateNonce()` SHALL encode 16 and 12 cryptographically random bytes as 32 and 24 hex digits respectively. Both modes SHALL continue interpreting legacy strings of 16 and 12 characters respectively as UTF-8.

#### Scenario: Generated parameters

- **WHEN** a caller supplies a generated hex value
- **THEN** the cipher uses the decoded bytes

#### Scenario: Legacy text parameter

- **WHEN** an old 12-character GCM nonce consists entirely of hex characters
- **THEN** decryption uses its UTF-8 bytes

#### Scenario: Missing GCM nonce

- **WHEN** a caller omits the nonce on encryption or decryption
- **THEN** the call rejects

### Requirement: Classic wire formats

The classic APIs SHALL use UTF-8 text and 32-byte ASCII string keys with no implicit MD5 derivation. Both SHALL return standard Base64. CBC SHALL use PKCS#7 padding. GCM SHALL use empty additional authenticated data and append a 16-byte tag.

#### Scenario: Cross-library read

- **WHEN** an independent reader decodes the classic ciphertext and uses the matching mode, original key bytes and parameter bytes
- **THEN** it recovers the message

#### Scenario: GCM authentication

- **WHEN** a caller changes the classic GCM tag
- **THEN** decryption rejects
