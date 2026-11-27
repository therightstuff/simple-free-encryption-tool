# crypto-verification Specification

## Purpose
Define known-answer and cross-runtime verification for the cryptographic interfaces.
## Requirements
### Requirement: Independent known answers

The AES-GCM tests SHALL verify the published OpenSSL AES-256-GCM empty and single-block zero plaintext fixtures using exact ciphertext and tag bytes in both directions.

#### Scenario: Known answer changes

- **WHEN** encryption produces a different tag or decryption mishandles an expected fixture
- **THEN** the corresponding test fails

### Requirement: Cross-runtime checks

Pull-request CI SHALL build the bundle and run a real Chromium-based browser against the Node package for sealed messages, classic CBC and classic GCM.

#### Scenario: Interoperability

- **WHEN** the check runs against the rebuilt browser bundle
- **THEN** each runtime decrypts output from the other and the browser's extracted sealed fields match the stored payload

#### Scenario: Node library interoperability

- **WHEN** tests supply extracted fields to native Node crypto with the documented additional data
- **THEN** authenticated decryption succeeds for empty and nonempty text

