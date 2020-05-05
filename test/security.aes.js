const assert = require('assert');
const aes = require('../src/security.aes');

describe('aes', function() {
    let secret = "my secret";
    let plaintext = "plaintext";

    let correctIv = "thisisacorrectiv";
    let incorrectIv = "notyourcorrectiv";
    let invalidIv = "invalidiv";

    let encrypted = aes.encrypt(secret, plaintext, correctIv);
    let encryptedWithOtherIv = aes.encrypt(secret, plaintext, incorrectIv);
    let encryptedWithNullIv = aes.encrypt(secret, plaintext);
    let expectedEncrypted = "QHYtdyk+N7++AMlapdOjdw==";

    describe('aes.encrypt encrypts correctly', function() {
        it('returns encrypted text different from plaintext', function() {
            assert.notEqual(encrypted, plaintext);
        });
        it('returns expected encrypted text', function() {
            assert.equal(encrypted, expectedEncrypted);
        });
        it('returns different encrypted text with another iv', function() {
            assert.notEqual(encrypted, encryptedWithOtherIv);
        });
    });

    describe('aes.decrypt decrypts correctly', function() {
        it('returns correctly decrypted plaintext with iv', function() {
            assert.equal(aes.decrypt(secret, encrypted, correctIv), plaintext);
        });
        it('returns correctly decrypted plaintext with default iv', function() {
            assert.equal(aes.decrypt(secret, encryptedWithNullIv), plaintext);
        });
        it('requires correct iv', function() {
            assert.notEqual(aes.decrypt(secret, encrypted, incorrectIv), plaintext);
        });
    });

    describe('aes.encrypt handles invalid values', function() {
        it('throw an error on invalid iv', function() {
            assert.throws(() => {
                aes.encrypt(secret, plaintext, invalidIv);
            }, (err) => err.message === aes.INVALID_IV_ERROR)
        });
        it('throw an error on invalid cipher data', function() {
            assert.throws(() => {
                aes.encrypt(secret, null, correctIv);
            }, (err) => err.message.substr(0, 19) === 'The "data" argument')
        });
        it('throw an error on invalid key', function() {
            assert.throws(() => {
                aes.encrypt();
            }, (err) => err.message === aes.INVALID_KEY_ERROR)
        });
    });

    describe('aes.decrypt handles invalid values', function() {
        it('throw an error on invalid iv', function() {
            assert.throws(() => {
                aes.decrypt(secret, plaintext, invalidIv);
            }, (err) => err.message === aes.INVALID_IV_ERROR)
        });
        it('throw an error on invalid cipher data', function() {
            assert.throws(() => {
                aes.decrypt(secret, null, correctIv);
            }, (err) => err.message.substr(0, 19) === 'The "data" argument')
        });
        it('throw an error on invalid key', function() {
            assert.throws(() => {
                aes.decrypt();
            }, (err) => err.message === aes.INVALID_KEY_ERROR)
        });
  });

  describe('aes.generateKey', function() {
      it('returns md5 hash', function() {
          assert.equal(aes.generateKey().length, 32);
      });
    });
});
