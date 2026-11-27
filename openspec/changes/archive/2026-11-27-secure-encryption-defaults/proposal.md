## Why

The classic CBC API silently reused a fixed IV when callers omitted it. Developers also had to manage keys, nonces and ciphertext formats themselves to exchange encrypted text between Node.js and a browser.

## What Changes

- Provide authenticated text encryption with generated keys, automatic nonce management, a versioned format, and helpers for external libraries.
- **BREAKING** Require an IV for CBC encryption. Preserve IV-less legacy reads with a warning.
- **BREAKING** Generate full-width IVs and nonces. Consumers storing generated strings in fixed-width fields need space for 32 or 24 hex digits.
- Default the interactive demo to GCM. Document both the simple API and classic formats, label legacy checksums, and publish a private reporting contact.
- Check the package and its browser bundle against published vectors and real-browser interoperability tests.

## Capabilities

### New Capabilities

- `sealed-messages` covers key generation, sealing, opening and field extraction.
- `classic-aes` covers explicit parameters, string encodings and legacy reads.
- `encryption-demo` covers interactive encryption defaults and decryption inputs.
- `developer-guidance` covers npm onboarding, interoperability documentation and private reporting.
- `crypto-verification` covers release examples, known-answer tests and cross-runtime checks.

### Modified Capabilities

This is the first OpenSpec change in the repository.

## Impact

The Node package and browser bundle share the AES implementation. Playwright Core is a development dependency of the browser check. This proposal records the existing working-tree changes. Publishing the package and transferring the repository are separate maintainer operations.
