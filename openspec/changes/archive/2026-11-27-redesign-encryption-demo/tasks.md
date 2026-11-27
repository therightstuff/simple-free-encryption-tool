## 1. Demo structure and presentation

- [x] 1.1 Replace the table-based `dist/index.html` layout with responsive semantic tool sections for AES, RSA, SHA-256, and legacy MD5, all expanded on initial load.
- [x] 1.2 Add a cohesive modern visual system for layout, typography, forms, actions, status feedback, narrow viewports, keyboard focus, and reduced-motion-safe transitions without adding dependencies.
- [x] 1.3 Preserve the current crypto calls, initial AES-GCM selection, fresh AES IV/nonce behavior, text/file paths, and explicit labels/IDs needed by the distributed demo.

## 2. Deliberate local exports

- [x] 2.1 Implement an accessible icon-only copy control for each text value and verification result, with current-value copying, a standalone-browser fallback, and success/failure feedback that never contains copied content.
- [x] 2.2 Implement separate public/private RSA PEM download controls beside their copy controls; create UTF-8 downloads named `sfet-public-key.pem` and `sfet-private-key.pem` only when the corresponding current field is non-empty, and release temporary object URLs after use.
- [x] 2.3 Ensure the demo does not add cookies, localStorage, sessionStorage, IndexedDB, automatic clipboard writes, automatic downloads, value transmission, or secret-bearing diagnostics.

## 3. Verification

- [x] 3.1 Update `scripts/browser-interop.mjs` to use stable test selectors while asserting semantic label associations and preserving AES interoperability coverage against the built demo.
- [x] 3.2 Extend the real-browser check to cover initially expanded sections, GCM initial selection, accessible copy controls, successful and failed copy behavior, separate current-value PEM downloads, disabled/empty-key downloads, and absence of browser persistence or implicit exports.
- [x] 3.3 Review the rendered page at narrow and wide viewports with keyboard-only navigation, including focus visibility, disclosure operation, icon-button names/titles, responsive layout, and non-disruptive feedback.
- [x] 3.4 Run `npm test`, rebuild the browser bundle, and run `npm run test:browser` against the resulting distributable page.

## 4. Action-flow feedback refinement

- [x] 4.1 Place AES, RSA, signing, and verification actions between their source and destination fields; put AES mode, key, and nonce guidance in the order users need it.
- [x] 4.2 Move copy and download controls inside their value fields, reduce their visual weight, and retain accessible names and titles.
- [x] 4.3 Add local status regions and field-specific invalid states for known input failures, then cover the AES missing-key path in the browser check.
- [x] 4.4 Clear superseded AES field errors after a successful encryption or decryption, and clear decryption feedback when a subsequent encryption begins, including when that encryption fails; cover both paths in the browser check.

## 5. Action locality and exclusive key generation

- [x] 5.1 Position AES encryption and decryption status feedback above their respective source fields, and cover the locations in the browser check.
- [x] 5.2 Replace generic AES file-operation failures with local, safe, actionable feedback.
- [x] 5.3 Make RSA key generation single-flight by disabling its controls and guarding the handler until it settles, with browser coverage.

## 6. Trigger-local feedback and proportional icons

- [x] 6.1 Keep RSA generation and transform feedback alongside its respective action controls.
- [x] 6.2 Give every copy/download icon a complete view box and a proportionate, padded size inside its compact button.
- [x] 6.3 Bind asynchronous feedback to its initiating action so concurrent actions cannot redirect it.

## 7. Preserve live work during initialization

- [x] 7.1 Make the demo initializer idempotent and non-destructive, with browser coverage for retained draft input.
