## ADDED Requirements

### Requirement: Release-matched onboarding

The npm README SHALL explain local Node/browser use, preserve existing badges and images unless removal is explicitly authorized, link the GitHub HTML preview, and demonstrate the package shipping with the README.

#### Scenario: New developer

- **WHEN** a reader follows the Node or browser example
- **THEN** they can generate a key, seal text and open it with the same key

#### Scenario: Learning the concepts

- **WHEN** a reader consults Cryptography 101
- **THEN** they find symmetric encryption, nonce uniqueness, authentication, RSA shared-secret transport and signature verification explained in everyday language

### Requirement: Key handling and interoperability reference

Public guides SHALL cover key persistence, explicit export and import, recovery limits, length visibility, replay and per-key rotation guidance, classic method signatures and field encodings, and sealed-field extraction with an independent decryption example.

#### Scenario: Integration

- **WHEN** a developer needs to match an external cipher
- **THEN** the reference specifies the key, IV, padding, tag and additional-data conventions for their format

#### Scenario: Restart

- **WHEN** a developer plans to store sealed records
- **THEN** the guide explains why they need durable access to the original key and how browser and server storage differ

### Requirement: Reporting and handover

Public documentation SHALL direct private reports to security@industrialcuriosity.com, identify MD5 as legacy, and keep the local repository-transfer handover outside version control and public onboarding.

#### Scenario: Report a vulnerability

- **WHEN** a reader follows the README security link
- **THEN** the policy explains where to report privately using synthetic examples

#### Scenario: Maintainer handover

- **WHEN** a maintainer keeps the transfer guide under the root `.docs/` directory
- **THEN** Git ignores the guide and the public README does not link it
