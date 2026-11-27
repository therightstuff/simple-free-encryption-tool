# Changelog

## [Unreleased]

### Changed

- AES now provides authenticated sealed messages with generated AES-256-GCM keys, explicit export controls, and interoperable sealed-message field extraction.
- Classic AES requires explicit CBC encryption IVs, generates full-width IVs and nonces, and retains documented legacy-decryption compatibility.
- Documentation and CI now cover browser interoperability, key handling, classic formats, and private security reporting.
- The browser demo groups AES, RSA, and checksum tools into expandable sections. Each action displays feedback beside its controls and highlights fields that need correction.
- Users can copy individual values and download RSA public and private keys separately as PEM files. The demo processes values locally and keeps them in memory.
