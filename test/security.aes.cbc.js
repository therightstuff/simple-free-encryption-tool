const assert = require('node:assert');
const aes = require('../src/security.aes');

describe('aes.cbc', function() {
    jest.setTimeout(30000);
    let invalidKey = "my secret";
    let validKey = "my new 32 character secret key!!";
    let plaintext = "plaintext";

    let correctIv = "thisisacorrectiv";
    let generatedIv = aes.cbc.generateIv();
    let incorrectIv = "notyourcorrectiv";
    let invalidIv = "invalidiv";

    let encrypted, encryptedWithOtherIv, encryptedWithGeneratedIv, encryptedWithNullIv;
    const expectedEncrypted = "4s1QNHkb3u17QxIqhJf8BA==";

    beforeAll(async function() {
        encrypted = await aes.cbc.encrypt(validKey, plaintext, correctIv);
        encryptedWithOtherIv = await aes.cbc.encrypt(validKey, plaintext, incorrectIv);
        encryptedWithGeneratedIv = await aes.cbc.encrypt(validKey, plaintext, generatedIv);
        encryptedWithNullIv = await aes.cbc.encrypt(validKey, plaintext);
    });

    describe('aes.cbc.encrypt encrypts correctly', function() {
        it('returns encrypted text different from plaintext', function() {
            assert.notStrictEqual(encrypted, plaintext);
        });
        it('returns expected encrypted text', function() {
            assert.strictEqual(encrypted, expectedEncrypted);
        });
        it('returns different (generated) encrypted text different from plaintext', function() {
            assert.notStrictEqual(encryptedWithGeneratedIv, plaintext);
        });
        it('returns different encrypted text with generated iv', function() {
            assert.notStrictEqual(encrypted, encryptedWithGeneratedIv);
        });
        it('returns different encrypted text different from plaintext', function() {
            assert.notStrictEqual(encryptedWithOtherIv, plaintext);
        });
        it('returns different encrypted text with another iv', function() {
            assert.notStrictEqual(encrypted, encryptedWithOtherIv);
        });
    });

    describe('aes.cbc.decrypt decrypts correctly', function() {
        it('returns correctly decrypted plaintext with iv', async function() {
            assert.strictEqual(await aes.cbc.decrypt(validKey, encrypted, correctIv), plaintext);
        });
        it('returns correctly decrypted plaintext with generated iv', async function() {
            assert.strictEqual(await aes.cbc.decrypt(validKey, encryptedWithGeneratedIv, generatedIv), plaintext);
        });
        it('returns correctly decrypted plaintext with default iv', async function() {
            assert.strictEqual(await aes.cbc.decrypt(validKey, encryptedWithNullIv), plaintext);
        });
        it('requires correct iv', async function() {
            assert.notStrictEqual(await aes.cbc.decrypt(validKey, encrypted, incorrectIv), plaintext);
        });
    });

    describe('aes.cbc.encrypt handles invalid values', function() {
        it('throws an error on invalid iv', async function() {
            await assert.rejects(
                () => aes.cbc.encrypt(validKey, plaintext, invalidIv),
                (err) => err.message === aes.cbc.INVALID_IV_ERROR
            );
        });
        it('throws an error on invalid cipher data', async function() {
            await assert.rejects(
                () => aes.cbc.encrypt(validKey, null, correctIv)
            );
        });
        it('throws an error on invalid key', async function() {
            await assert.rejects(
                () => aes.cbc.encrypt(invalidKey, plaintext, correctIv),
                (err) => err.message === aes.cbc.INVALID_KEY_ERROR
            );
        });
    });

    describe('aes.cbc.decrypt handles invalid values', function() {
        it('throws an error on invalid iv', async function() {
            await assert.rejects(
                () => aes.cbc.decrypt(validKey, plaintext, invalidIv),
                (err) => err.message === aes.cbc.INVALID_IV_ERROR
            );
        });
        it('uses fallback message when decode error has no message', async function() {
            const originalAtob = globalThis.atob;
            globalThis.atob = () => { throw {}; };
            try {
                await assert.rejects(
                    () => aes.cbc.decrypt(validKey, 'any-ciphertext', correctIv),
                    (err) => err.message === 'AES-CBC decryption failed (invalid ciphertext)'
                );
            } finally {
                globalThis.atob = originalAtob;
            }
        });
        it('throws a normalized error on malformed base64 ciphertext', async function() {
            await assert.rejects(
                () => aes.cbc.decrypt(validKey, '%%%not-base64%%%', correctIv),
                (err) => err.message.toLowerCase().includes('invalid')
            );
        });
        it('throws an error on invalid cipher data', async function() {
            await assert.rejects(
                () => aes.cbc.decrypt(validKey, null, correctIv)
            );
        });
        it('throws an error on invalid key', async function() {
            await assert.rejects(
                () => aes.cbc.decrypt(invalidKey, plaintext, correctIv),
                (err) => err.message === aes.cbc.INVALID_KEY_ERROR
            );
        });
    });

    describe('aes.cbc.validateIv', function() {
        it('does not throw an error on valid iv', function() {
            assert.doesNotThrow(() => {
                aes.cbc.validateIv(correctIv);
            });
        });
        it('throws an error on invalid iv', function() {
            assert.throws(() => {
                aes.cbc.validateIv(invalidIv);
            }, (err) => err.message === aes.cbc.INVALID_IV_ERROR)
        });
    });
});
