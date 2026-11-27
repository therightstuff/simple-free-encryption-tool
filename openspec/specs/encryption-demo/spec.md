# encryption-demo Specification

## Purpose
Define initial AES behavior and user guidance in the browser demo.
## Requirements
### Requirement: Safe initial mode and fresh parameters

The demo SHALL select GCM initially and generate a fresh parameter for every text or file encryption in either selectable mode.

#### Scenario: Repeated encryption

- **WHEN** a user encrypts again using the same key
- **THEN** the demo generates and displays the new nonce or IV to save with that result

#### Scenario: Decryption

- **WHEN** a user opens a previous result
- **THEN** the demo uses the supplied parameter and supports leaving the CBC IV blank for legacy data

### Requirement: Explain the controls

The demo SHALL describe nonce uniqueness and parameter storage and label MD5 as a legacy checksum.

#### Scenario: First visit

- **WHEN** a visitor selects GCM or opens the MD5 tool
- **THEN** the relevant explanation or legacy label appears beside the controls

