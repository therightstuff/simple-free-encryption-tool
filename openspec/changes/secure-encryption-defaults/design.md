## Context

A Node module and a browser global expose the same AES implementation. Existing applications may have stored just the classic ciphertext, or kept its IV in a fixed-width column. New callers want one string they can store without managing separate encryption parameters.

## Goals / Non-Goals

Provide a simple authenticated text API, preserve access to earlier records, and let another implementation decrypt both formats from documented inputs. Key custody, key distribution, replay tracking, publishing and repository ownership remain application or maintainer responsibilities.

## Decisions

- **Add a sealed format alongside the classic formats.** Generating the nonce and authenticating the version in one operation reduces caller mistakes. Changing the classic GCM output in place would make old readers misinterpret its bytes. All sealed readers share one decoder, including helpers that inspect fields without verifying authenticity.
- **Use native CryptoKeys for sealed messages.** A non-extractable default limits accidental exposure of raw key material. Explicit opt-in at generation supports applications that must manage backups or key distribution. Default non-extractability still permits decryption by code holding the key.
- **Preserve legacy parameter interpretation by length.** Full-width hex outputs can be distinguished from old text values, including old values that happen to look hexadecimal. A CBC read fallback recovers existing records. Rejecting IV-less writes prevents silent creation of new fixed-IV records. The deprecated top-level CBC aliases and synchronous RSA generator were already absent. Documentation removes obsolete examples.
- **Exercise the distributed surfaces.** Published vectors catch mutually compatible mistakes in encrypt and decrypt. Playwright Core drives a real browser with native Web Crypto and loads the built bundle. The browser check uses disposable key material when it needs the same secret in both runtimes.
- **Keep operator material local.** The ignored handover guide covers moving the GitHub repository while preserving the npm name. The release README, public usage guides and security policy serve package users. The audit report supplies historical motivation, rather than an acceptance score. OpenSpec configuration records the audience and release-example conventions.

## Risks / Trade-offs

Losing the only usable key makes saved messages unreadable. The guides explain persistence and explicit export. Sealed records reveal message length and can be replayed. Applications that act on a message once must track its identity. The package does not count nonce usage across systems. Documentation assigns rotation to the application. CBC still lacks authentication even when its IV is fresh.

## Migration Plan

1. Treat the required CBC IV and wider generated parameters as breaking changes. Widen fixed-width parameter storage and update writers to save the generated value with each classic ciphertext.
2. Deploy compatible readers before writing sealed messages or wider parameters. Retain the matching decoder and key for each existing format. Existing records require no bulk rewrite.
3. If rolling back writers, keep readers capable of opening records already written by the new version. Older code cannot open sealed records or interpret the new hex parameters.

## Open Questions

No unresolved design decisions for the captured implementation. Release timing and the GitHub transfer remain separate operator decisions.
