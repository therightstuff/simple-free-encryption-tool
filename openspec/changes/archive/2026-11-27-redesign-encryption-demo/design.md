## Context

`dist/index.html` is a standalone browser demo that currently combines hashing, RSA, and classic AES controls in a centered table layout. Its JavaScript operates entirely in the page, and RSA key generation returns PKCS#8 public and private PEM strings. The redesigned page must remain usable from a local file or a simple static host, without sending or retaining values.

## Goals / Non-Goals

**Goals:**

- Make the demo easy to scan and use at narrow and wide viewport sizes while continuing to demonstrate every package capability.
- Preserve the existing AES-GCM default, fresh encryption parameters, file-download behavior, identifiers, and crypto calls.
- Make an explicit user action the only way a value reaches the system clipboard or a downloaded file.
- Provide keyboard-accessible, self-explanatory controls and clear feedback without revealing secrets in status text or logs.

**Non-Goals:**

- Changing package cryptographic APIs, adding sealed-message handling, or changing AES/RSA/checksum algorithms.
- Saving inputs, keys, results, preferences, or disclosure state in browser storage.
- Uploading, synchronizing, sharing, or otherwise transmitting any entered/generated value.
- Adding an icon, UI, or persistence dependency.

## Decisions

### Use responsive semantic disclosure sections, initially open

The introductory context and each tool (AES, RSA, SHA-256, and legacy MD5) will use a native `details`/`summary` or equivalent semantic disclosure pattern with its expanded state set on initial load. Native disclosure preserves a compact scan path without hiding functionality, provides keyboard interaction, and requires no state persistence. The page will use a single responsive content column and CSS grid/flex layouts rather than data tables for form structure.

### Retain classic AES-GCM as the primary interactive flow

The existing demo takes a transferable 32-character key and a visible nonce/IV, which users can deliberately export and use with another implementation. A sealed-message flow would require a separate decision about safe key export and recovery. The redesign therefore retains the current GCM-default classic AES controls, mode descriptions, fresh parameters, and optional file workflow.

### Export only when the user invokes a per-value action

Every readable or editable text value and status result receives an adjacent copy button with an embedded standard copy icon, `title`, and accessible name. Icons use a 24-unit view box and size proportionately inside their buttons, leaving visible padding without clipping. Selectors and the file chooser do not receive copy actions because they do not represent portable result values. Copy uses `navigator.clipboard.writeText` when available and a local in-page fallback for standalone contexts. It never reads/writes browser storage, sends the copied value, or includes a value in feedback or diagnostics.

Generated or supplied RSA PEM fields additionally receive a save-icon download button. Activation creates a short-lived text blob from the current field value and downloads it as `sfet-public-key.pem` or `sfet-private-key.pem`; the object URL is revoked after use. The controls are unavailable for an empty corresponding field. Public and private keys are deliberately separate to prevent a routine public-key export from also exporting the private key.

### Use stable machine selectors and preserve semantic labels

Existing control IDs and explicit labels remain stable where possible. Browser checks will use dedicated `data-testid` attributes for demo-specific wiring so visual label changes do not break interoperability checks. Labels, `aria-describedby` relationships, focus styles, and icon-button names remain part of the user interface contract.

### Mount the demo once without replacing the document

The demo initializer creates its surface only when it is absent. It appends the initial surface and removes the inert legacy template without replacing `document.body`, so a later initializer call cannot discard live values or listeners.

### Keep feedback local and non-disruptive

Copy, download, generation, and crypto feedback will identify the completed or failed action without echoing secrets. Each action owns a nearby reserved feedback region so a user does not need to search the page after acting, and asynchronous work retains its initiating action's region even if another action starts before it finishes. AES text encryption feedback appears above its unencrypted source field, decryption feedback above its encrypted source field, and RSA key-generation feedback beside the generation controls. File-operation failures state that the selected file remains unchanged and give the next safe action. Known input failures also mark the field that needs correction and clear that mark when the field changes, when a successful transformation supersedes the failed flow, or when a related replacement action begins.

### Keep RSA key generation single-flight

RSA key generation writes a shared key-pair result and is not safe to start twice. The demo disables its trigger and the selected key-size control while generation is pending, while the handler independently rejects a concurrent invocation. A `finally` path restores both controls after success or failure.

### Arrange transformations as source, action, result

AES and RSA transformations place their action controls between the source and destination fields. AES presents mode guidance first, then the key required by both directions, then the nonce/IV required to read a saved result. Copy and download icons sit inside the relevant fields' top-right corners to keep export available without interrupting that flow.

## Risks / Trade-offs

- [Clipboard contents can be visible to other local applications] → Copy remains a separate deliberate action, and private-key copy is clearly labeled.
- [Clipboard API is unavailable for some file-origin or permission configurations] → Use an in-page fallback where supported; otherwise show a focused, actionable error while leaving the value visible for manual selection.
- [A downloaded private key can be stored insecurely by the user] → Export no file automatically; name the action and field clearly and preserve separate public/private downloads.
- [Disclosure widgets could obscure capabilities] → All are expanded initially, with concise summaries and responsive spacing.
- [Visual edits could break distributed-demo checks] → Preserve runtime APIs/IDs, add stable selectors, and exercise the built `dist` page in a real browser.

## Migration Plan

1. Replace only the demo presentation and client interaction helpers; retain the established crypto functions and bundle references.
2. Run unit and real-browser checks against the rebuilt distributed page, including AES interoperability.
3. If a regression requires rollback, restore the previous static page; no user data needs migration because the demo deliberately retains no browser state.

## Open Questions

None. The scope is implementation-ready.
