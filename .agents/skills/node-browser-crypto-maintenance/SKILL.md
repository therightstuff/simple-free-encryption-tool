---
name: node-browser-crypto-maintenance
description: Keep this package correct for both Node.js and browser usage whenever code changes touch cryptography, exports, runtime behavior, examples, or docs. Use for RSA/AES updates, API changes, module inclusion changes, bundle/export changes, and any request that could drift README or dist/index.html from implementation.
---

# Node-Browser Crypto Maintenance

Maintain runtime parity and documentation parity for this package.

## When to Use

Use this skill whenever work may affect either runtime surface:

- RSA or AES behavior changes
- hash behavior changes
- import or dependency changes touching crypto paths
- changes to public package exports
- changes to browser-exposed API surface
- changes to validation or error behavior
- updates to examples or usage snippets

## Invariants

1. Node and browser surfaces stay intentionally aligned.
2. Shared crypto behavior remains runtime-compatible.
3. README and dist/index.html must match current behavior after code changes.
4. Examples must reflect real sync/async call semantics.

## Procedure

1. Identify affected surfaces.
- Node package surface: CommonJS exports consumed by server-side users.
- Browser surface: bundled global API consumed by dist/index.html.
- Crypto behavior: key size rules, IV/nonce rules, validation and error paths.

2. Apply runtime-safe inclusion rules.
- **Sync operations**: Use pure-JavaScript implementations (e.g., `md5`, `js-sha256`) to ensure sync works identically in both Node.js and browser contexts. Runtime-specific APIs like `node:crypto` cannot be bundled to browsers.
- **Async operations**: Prefer native Web Crypto API (`globalThis.crypto.subtle`) when available; it is async-only but standard across both runtimes.
- Keep crypto namespaces exposed consistently in both runtime entrypoints unless a difference is intentional and documented.
- Do not introduce Node-only runtime dependencies into shared crypto modules unless there is a deliberate compatibility plan documented in README.
- If a behavior is intentionally runtime-specific, document that difference in README and ensure examples show the correct runtime context.

3. Verify RSA/AES behavioral contracts.
- RSA flows: key generation, encrypt/decrypt, sign/verify behaviors remain coherent with current package contracts.
- AES flows: key length, IV/nonce length, and mode-specific safety constraints remain enforced.
- Error behavior remains deterministic for invalid input.

4. Update docs and demo assets in the same turn.
- Update README usage and API notes for any behavior or semantics change.
- Update dist/index.html text or UI behavior when runtime behavior or user guidance changes.
- Ensure README and dist/index.html use matching guidance for key handling, IV/nonce handling, and async usage.
- Sweep all occurrences of touched API symbols in README and dist/index.html (not only one section) and verify each call site uses correct sync/async semantics.

5. Validate completion.
- Run targeted tests for changed behavior.
- Run full tests when change scope is broad.
- Run build when browser bundle or demo behavior is affected.
- Re-open README and dist/index.html to confirm examples and warnings still match implementation.

## Decision Branches

- If change is implementation-only and user-visible behavior is unchanged:
  - Keep docs unchanged only after explicit verification that examples and guidance remain accurate.
- If change affects behavior, validation, errors, or async/sync semantics:
  - Update README and dist/index.html in the same change set, then perform an occurrence sweep for the touched APIs to catch stale examples.
- If change affects only one runtime intentionally:
  - Add explicit runtime note in README and avoid ambiguous examples.

## Completion Checklist

- Node and browser crypto surfaces reviewed
- Runtime inclusion constraints respected
- RSA/AES contracts verified
- README updated or explicitly confirmed current
- dist/index.html updated or explicitly confirmed current
- Tests/build run at appropriate scope
