const assert = require('assert');
const aes = require('../src/security.aes');

describe('aes', function() {
    let secret = "my secret";
    let plaintext = "plaintext";

    let correctIv = "thisisacorrectiv";
    let generatedIv = aes.generateIv();
    let incorrectIv = "notyourcorrectiv";
    let invalidIv = "invalidiv";

    let encrypted = aes.encrypt(secret, plaintext, correctIv);
    let encryptedWithOtherIv = aes.encrypt(secret, plaintext, incorrectIv);
    let encryptedWithGeneratedIv = aes.encrypt(secret, plaintext, generatedIv);
    let encryptedWithNullIv = aes.encrypt(secret, plaintext);
    let expectedEncrypted = "QHYtdyk+N7++AMlapdOjdw==";

    describe('aes.encrypt encrypts correctly', function() {
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

    describe('aes.decrypt decrypts correctly', function() {
        it('returns correctly decrypted plaintext with iv', function() {
            assert.strictEqual(aes.decrypt(secret, encrypted, correctIv), plaintext);
        });
        it('returns correctly decrypted plaintext with generated iv', function() {
            assert.strictEqual(aes.decrypt(secret, encryptedWithGeneratedIv, generatedIv), plaintext);
        });
        it('returns correctly decrypted plaintext with default iv', function() {
            assert.strictEqual(aes.decrypt(secret, encryptedWithNullIv), plaintext);
        });
        it('requires correct iv', function() {
            assert.notStrictEqual(aes.decrypt(secret, encrypted, incorrectIv), plaintext);
        });
    });

    describe('aes.encrypt handles invalid values', function() {
        it('throws an error on invalid iv', function() {
            assert.throws(() => {
                aes.encrypt(secret, plaintext, invalidIv);
            }, (err) => err.message === aes.INVALID_IV_ERROR)
        });
        it('throws an error on invalid cipher data', function() {
            assert.throws(() => {
                aes.encrypt(secret, null, correctIv);
            }, (err) => err.message.substr(0, 19) === 'The "data" argument')
        });
        it('throws an error on invalid key', function() {
            assert.throws(() => {
                aes.encrypt();
            }, (err) => err.message === aes.INVALID_KEY_ERROR)
        });
    });

    describe('aes.decrypt handles invalid values', function() {
        it('throws an error on invalid iv', function() {
            assert.throws(() => {
                aes.decrypt(secret, plaintext, invalidIv);
            }, (err) => err.message === aes.INVALID_IV_ERROR)
        });
        it('throws an error on invalid cipher data', function() {
            assert.throws(() => {
                aes.decrypt(secret, null, correctIv);
            }, (err) => err.message.substr(0, 19) === 'The "data" argument')
        });
        it('throws an error on invalid key', function() {
            assert.throws(() => {
                aes.decrypt();
            }, (err) => err.message === aes.INVALID_KEY_ERROR)
        });
    });

    // DEPRECATED
    describe('aes.generateKey', function() {
        it('returns 32-character randomly generated string', function() {
            assert.strictEqual(aes.generateKey().length, 32);
        });
    });
});
