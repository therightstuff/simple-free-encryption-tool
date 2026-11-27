## Why

The standalone encryption demo is functional but visually dated, table-driven, and difficult to scan. It needs a modern, accessible interface that demonstrates the package clearly while making deliberate export of keys and results straightforward.

## What Changes

- Redesign the browser demo into a responsive, task-oriented interface with clear controls, results, and cryptographic guidance.
- Present every tool as an expanded-by-default disclosure section so visitors can scan or focus on one capability without hiding package functionality.
- Keep all working values in page memory only: do not add browser persistence, automatic transfers, or network submission.
- Add explicit icon-only copy actions to each user-entered or generated value, with accessible names, tooltips, and safe success or failure feedback.
- Add separate, explicit downloads for generated RSA public and private PKCS#8 PEM keys, next to their copy actions.
- Retain the existing AES, RSA, checksum, text, and file-encryption behavior, including GCM as the default and MD5's legacy warning.
- Replace fragile browser-test label lookups with stable selectors while preserving semantic labels and verifying the redesigned demo loads its distributed browser bundle.

## Capabilities

### New Capabilities

- `encryption-demo-interface`: Responsive, accessible interaction and disclosure structure for the standalone browser demo.
- `demo-value-export`: Explicit clipboard copying and RSA PEM key downloads without browser persistence or automatic data export.

### Modified Capabilities

None.

## Impact

The primary change is to `dist/index.html`, its inline styles and client-side behavior. `scripts/browser-interop.mjs` will be updated to validate stable demo wiring, and browser-level checks will cover the redesigned controls and explicit export behavior. No runtime package API, server, dependency, or browser-storage integration changes.
