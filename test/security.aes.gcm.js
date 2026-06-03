const assert = require('node:assert');
const aes = require('../src/security.aes');

// AES-256-GCM is an authenticated encryption (AEAD) scheme.
//
// Unlike AES-CBC which uses an IV, GCM requires a NONCE (number used once).
// The distinction matters:
//   - CBC IV reuse leaks information about common plaintext prefixes but is not
//     immediately catastrophic.
//   - GCM nonce reuse with the same key completely destroys both confidentiality
//     AND the authentication tag for every affected message. It can also allow
//     an attacker to recover the key. Nonces MUST always be explicitly provided
//     and MUST be unique per (key, message) pair. No default nonce is supplied.
//
// Use aes.gcm.generateNonce() to produce a fresh nonce for every encryption.

describe('aes.gcm', function() {
    jest.setTimeout(30000);
    let invalidKey = "my secret";
    let validKey = "my new 32 character secret key!!";
    let plaintext = "plaintext";

    let correctNonce = "correctgcmiv";   // 12 characters
    let incorrectNonce = "wronggcmivxx";  // 12 characters, different
    let invalidNonce = "short";           // < 12 characters
    let generatedNonce = aes.gcm.generateNonce();

    let encrypted, encryptedWithOtherNonce, encryptedWithGeneratedNonce;

    beforeAll(async function() {
        encrypted = await aes.gcm.encrypt(validKey, plaintext, correctNonce);
        encryptedWithOtherNonce = await aes.gcm.encrypt(validKey, plaintext, incorrectNonce);
        encryptedWithGeneratedNonce = await aes.gcm.encrypt(validKey, plaintext, generatedNonce);
    });

    describe('aes.gcm.encrypt encrypts correctly', function() {
        it('returns encrypted text different from plaintext', function() {
            assert.notStrictEqual(encrypted, plaintext);
        });
        it('returns deterministic ciphertext for same key, message, and nonce', async function() {
            assert.strictEqual(await aes.gcm.encrypt(validKey, plaintext, correctNonce), encrypted);
        });
        it('returns different encrypted text with generated nonce', function() {
            assert.notStrictEqual(encrypted, encryptedWithGeneratedNonce);
        });
        it('returns different encrypted text with another nonce', function() {
            assert.notStrictEqual(encrypted, encryptedWithOtherNonce);
        });
        it('returns different (generated) encrypted text different from plaintext', function() {
            assert.notStrictEqual(encryptedWithGeneratedNonce, plaintext);
        });
        it('returns different encrypted text with another nonce different from plaintext', function() {
            assert.notStrictEqual(encryptedWithOtherNonce, plaintext);
        });
        it('nonce reuse with the same key produces identical ciphertext — demonstrating why nonce uniqueness is critical', async function() {
            // Two encryptions of the same plaintext with the same key and nonce
            // yield the same output. In GCM this also exposes the keystream,
            // allowing an attacker to XOR both ciphertexts and recover both
            // plaintexts, and potentially the authentication key.
            let first  = await aes.gcm.encrypt(validKey, plaintext, correctNonce);
            let second = await aes.gcm.encrypt(validKey, "different plaintext", correctNonce);
            assert.strictEqual(first, encrypted);
            assert.notStrictEqual(first, second);
        });
    });

    describe('aes.gcm.decrypt decrypts correctly', function() {
        it('returns correctly decrypted plaintext with nonce', async function() {
            assert.strictEqual(await aes.gcm.decrypt(validKey, encrypted, correctNonce), plaintext);
        });
        it('returns correctly decrypted plaintext with generated nonce', async function() {
            assert.strictEqual(await aes.gcm.decrypt(validKey, encryptedWithGeneratedNonce, generatedNonce), plaintext);
        });
        it('throws an error when decrypting with wrong nonce (authentication failure)', async function() {
            await assert.rejects(() => aes.gcm.decrypt(validKey, encrypted, incorrectNonce));
        });
        it('throws an error when decrypting with wrong key (authentication failure)', async function() {
            let otherKey = "another 32 character secret key!";
            await assert.rejects(() => aes.gcm.decrypt(otherKey, encrypted, correctNonce));
        });
        it('throws an error when ciphertext has been tampered with', async function() {
            // Web Crypto AES-GCM: ciphertext is followed by 16-byte auth tag.
            // Flip a byte in the ciphertext portion to trigger authentication failure.
            let buf = Buffer.from(encrypted, 'base64');
            buf[0] ^= 0xff;
            let tampered = buf.toString('base64');
            await assert.rejects(() => aes.gcm.decrypt(validKey, tampered, correctNonce));
        });
    });

    describe('aes.gcm.encrypt handles invalid values', function() {
        it('throws an error when no nonce is provided — nonce is mandatory for GCM', async function() {
            await assert.rejects(
                () => aes.gcm.encrypt(validKey, plaintext),
                (err) => err.message === aes.gcm.INVALID_NONCE_ERROR
            );
        });
        it('throws an error on invalid nonce (too short)', async function() {
            await assert.rejects(
                () => aes.gcm.encrypt(validKey, plaintext, invalidNonce),
                (err) => err.message === aes.gcm.INVALID_NONCE_ERROR
            );
        });
        it('throws an error on invalid cipher data', async function() {
            await assert.rejects(() => aes.gcm.encrypt(validKey, null, correctNonce));
        });
        it('throws an error on invalid key', async function() {
            await assert.rejects(
                () => aes.gcm.encrypt(invalidKey, plaintext, correctNonce),
                (err) => err.message === aes.gcm.INVALID_KEY_ERROR
            );
        });
        it('throws an error on missing key', async function() {
            await assert.rejects(
                () => aes.gcm.encrypt(undefined, plaintext, correctNonce),
                (err) => err.message === aes.gcm.INVALID_KEY_ERROR
            );
        });
    });

    describe('aes.gcm.decrypt handles invalid values', function() {
        it('throws an error when no nonce is provided — nonce is mandatory for GCM', async function() {
            await assert.rejects(
                () => aes.gcm.decrypt(validKey, encrypted),
                (err) => err.message === aes.gcm.INVALID_NONCE_ERROR
            );
        });
        it('throws an error on invalid nonce (too short)', async function() {
            await assert.rejects(
                () => aes.gcm.decrypt(validKey, encrypted, invalidNonce),
                (err) => err.message === aes.gcm.INVALID_NONCE_ERROR
            );
        });
        it('uses fallback message when decode error has no message', async function() {
            const originalAtob = globalThis.atob;
            globalThis.atob = () => { throw {}; };
            try {
                await assert.rejects(
                    () => aes.gcm.decrypt(validKey, 'any-ciphertext', correctNonce),
                    (err) => err.message === 'AES-GCM decryption failed (invalid ciphertext)'
                );
            } finally {
                globalThis.atob = originalAtob;
            }
        });
        it('throws a normalized error on malformed base64 ciphertext', async function() {
            await assert.rejects(
                () => aes.gcm.decrypt(validKey, '%%%not-base64%%%', correctNonce),
                (err) => err.message.toLowerCase().includes('invalid')
            );
        });
        it('uses fallback message when auth error has no message', async function() {
            const decryptSpy = jest.spyOn(globalThis.crypto.subtle, 'decrypt').mockRejectedValue({});
            try {
                await assert.rejects(
                    () => aes.gcm.decrypt(validKey, encrypted, correctNonce),
                    (err) => err.message === 'AES-GCM decryption failed (authentication error)'
                );
            } finally {
                decryptSpy.mockRestore();
            }
        });
        it('throws an error on invalid cipher data', async function() {
            await assert.rejects(() => aes.gcm.decrypt(validKey, null, correctNonce));
        });
        it('throws an error on invalid key', async function() {
            await assert.rejects(
                () => aes.gcm.decrypt(invalidKey, encrypted, correctNonce),
                (err) => err.message === aes.gcm.INVALID_KEY_ERROR
            );
        });
        it('throws an error on missing key', async function() {
            await assert.rejects(
                () => aes.gcm.decrypt(undefined, encrypted, correctNonce),
                (err) => err.message === aes.gcm.INVALID_KEY_ERROR
            );
        });
    });

    describe('aes.gcm.generateNonce', function() {
        it('returns a 12-character string', function() {
            assert.strictEqual(aes.gcm.generateNonce().length, 12);
        });
        it('returns different values on successive calls', function() {
            assert.notStrictEqual(aes.gcm.generateNonce(), aes.gcm.generateNonce());
        });
    });

    describe('aes.gcm.validateNonce', function() {
        it('does not throw on a valid 12-character nonce', function() {
            assert.doesNotThrow(() => { aes.gcm.validateNonce(correctNonce); });
        });
        it('throws an error on a nonce shorter than 12 characters', function() {
            assert.throws(() => {
                aes.gcm.validateNonce(invalidNonce);
            }, (err) => err.message === aes.gcm.INVALID_NONCE_ERROR);
        });
        it('throws an error on a null nonce', function() {
            assert.throws(() => {
                aes.gcm.validateNonce(null);
            }, (err) => err.message === aes.gcm.INVALID_NONCE_ERROR);
        });
    });

    describe('aes.gcm.validateKey', function() {
        it('does not throw on a valid 32-character key', function() {
            assert.doesNotThrow(() => { aes.gcm.validateKey(validKey); });
        });
        it('throws an error on a key shorter than 32 characters', function() {
            assert.throws(() => {
                aes.gcm.validateKey(invalidKey);
            }, (err) => err.message === aes.gcm.INVALID_KEY_ERROR);
        });
        it('throws an error on a null key', function() {
            assert.throws(() => {
                aes.gcm.validateKey(null);
            }, (err) => err.message === aes.gcm.INVALID_KEY_ERROR);
        });
    });
});
