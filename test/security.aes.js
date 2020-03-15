const assert = require('assert');
const aes = require('../src/security.aes');

describe('aes', function() {
    var secret = "secret";
    var plaintext = "plaintext";
    var encrypted = aes.encrypt(secret, plaintext);
    var expectedEncrypted = "MqRlloZr6NMxqOeFZOvtUA==";

    describe('aes.encrypt(secret, plaintext) != plaintext', function() {
        it('returns encrypted text different from plaintext', function() {
            assert.notEqual(encrypted, plaintext);
        });
        it('returns expected encrypted text', function() {
            assert.equal(encrypted, expectedEncrypted);
        });
    });

    describe('aes.decrypt(secret, encrypted) == plaintext', function() {
        it('returns correctly decrypted plaintext', function() {
            assert.equal(aes.decrypt(secret, encrypted), plaintext);
        });
    });

    describe('aes.encrypt handles invalid values', function() {
        it('throw an error on invalid cipher data', function() {
            assert.throws(() => {
                aes.encrypt(secret);
            }, (err) => err.message === 'The "data" argument must be one of type string, Buffer, TypedArray, or DataView. Received type undefined')
        });
        it('throw an error on invalid key', function() {
            assert.throws(() => {
                aes.encrypt();
            }, (err) => err.message === 'The "password" argument must be one of type string, Buffer, TypedArray, or DataView. Received type undefined')
        });
    });
    
    describe('aes.decrypt handles invalid values', function() {
        it('throw an error on invalid cipher data', function() {
            assert.throws(() => {
                aes.decrypt(secret);
            }, (err) => err.message === 'The "data" argument must be one of type string, Buffer, TypedArray, or DataView. Received type undefined')
        });
        it('throw an error on invalid key', function() {
            assert.throws(() => {
                aes.decrypt();
            }, (err) => err.message === 'The "password" argument must be one of type string, Buffer, TypedArray, or DataView. Received type undefined')
        });
  });

  describe('aes.generateKey', function() {
      it('returns md5 hash', function() {
          assert.equal(aes.generateKey().length, 32);
      });
    });  
});
