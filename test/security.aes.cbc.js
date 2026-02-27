const assert = require('node:assert');
const aes = require('../src/security.aes');

// DEPRECATED

describe('aes.cbc', function() {
    let invalidKey = "my secret";
    let validKey = "my new 32 character secret key!!";
    let plaintext = "plaintext";

    let correctIv = "thisisacorrectiv";
    let generatedIv = aes.cbc.generateIv();
    let incorrectIv = "notyourcorrectiv";
    let invalidIv = "invalidiv";

    let encrypted = aes.cbc.encrypt(validKey, plaintext, correctIv);
    let encryptedWithOtherIv = aes.cbc.encrypt(validKey, plaintext, incorrectIv);
    let encryptedWithGeneratedIv = aes.cbc.encrypt(validKey, plaintext, generatedIv);
    let encryptedWithNullIv = aes.cbc.encrypt(validKey, plaintext);
    let expectedEncrypted = "4s1QNHkb3u17QxIqhJf8BA==";

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
        it('returns correctly decrypted plaintext with iv', function() {
            assert.strictEqual(aes.cbc.decrypt(validKey, encrypted, correctIv), plaintext);
        });
        it('returns correctly decrypted plaintext with generated iv', function() {
            assert.strictEqual(aes.cbc.decrypt(validKey, encryptedWithGeneratedIv, generatedIv), plaintext);
        });
        it('returns correctly decrypted plaintext with default iv', function() {
            assert.strictEqual(aes.cbc.decrypt(validKey, encryptedWithNullIv), plaintext);
        });
        it('requires correct iv', function() {
            assert.notStrictEqual(aes.cbc.decrypt(validKey, encrypted, incorrectIv), plaintext);
        });
    });

    describe('aes.cbc.encrypt handles invalid values', function() {
        it('throws an error on invalid iv', function() {
            assert.throws(() => {
                aes.cbc.encrypt(validKey, plaintext, invalidIv);
            }, (err) => err.message === aes.cbc.INVALID_IV_ERROR)
        });
        it('throws an error on invalid cipher data', function() {
            assert.throws(() => {
                aes.cbc.encrypt(validKey, null, correctIv);
            }, (err) => err.message.substr(0, 19) === 'The "data" argument')
        });
        it('throws an error on invalid key', function() {
            assert.throws(() => {
                aes.cbc.encrypt(invalidKey, plaintext, correctIv);
            }, (err) => err.message === aes.cbc.INVALID_KEY_ERROR)
        });
    });

    describe('aes.cbc.decrypt handles invalid values', function() {
        it('throws an error on invalid iv', function() {
            assert.throws(() => {
                aes.cbc.decrypt(validKey, plaintext, invalidIv);
            }, (err) => err.message === aes.cbc.INVALID_IV_ERROR)
        });
        it('throws an error on invalid cipher data', function() {
            assert.throws(() => {
                aes.cbc.decrypt(validKey, null, correctIv);
            }, (err) => err.message.substr(0, 19) === 'The "data" argument')
        });
        it('throws an error on invalid key', function() {
            assert.throws(() => {
                aes.cbc.decrypt(invalidKey, plaintext, correctIv);
            }, (err) => err.message === aes.cbc.INVALID_KEY_ERROR)
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
