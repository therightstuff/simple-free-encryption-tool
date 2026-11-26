## 1. Classic encryption compatibility

- [x] 1.1 Require explicit CBC encryption IVs and retain the warning-backed legacy decrypt path with a fixture from the previous implementation.
- [x] 1.2 Generate full-width GCM nonces and CBC IVs and read both current hex and historical text encodings.

## 2. Sealed messages and interoperation

- [x] 2.1 Expose native AES-256-GCM key generation with explicit export opt-in through both runtimes.
- [x] 2.2 Implement authenticated versioned sealing and opening and cover Unicode, empty and large messages, invalid parameters, wrong keys and tampering.
- [x] 2.3 Expose IV, ciphertext and tag extraction through the shared parser and test the extracted fields with independent native decryption.

## 3. Demo, documentation and reporting

- [x] 3.1 Default the demo to GCM and generate fresh encryption parameters for text and files. Label MD5 for legacy checksums.
- [x] 3.2 Review the whole README for npm readers, preserve badges and the HTML preview, and supply beginner explanations plus checked Node and browser examples for the release.
- [x] 3.3 Document key storage, export and recovery, classic method encodings, sealed fields, native-library decryption and migration guidance.
- [x] 3.4 Publish the private reporting address in the security policy and README. Keep the handover guide in the ignored local directory.
- [x] 3.5 Record the project's release documentation conventions in OpenSpec configuration.

## 4. Verification and distribution

- [x] 4.1 Add published AES-256-GCM vectors and rebuild the distributable browser bundle.
- [x] 4.2 Add the real-browser interoperability script and pull-request workflow step. Verify both directions locally for sealed messages and both classic modes.
