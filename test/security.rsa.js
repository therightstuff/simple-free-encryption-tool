const assert = require('assert');
const rsa = require('../src/security.rsa');

describe('rsa', function() {
    var plaintext = "plaintext";
    var defaultKeySize = 2048;

    describe('synchronously generated key pair tests', function(){
        var generatedKeyPair = rsa.generateKeysSync();
        var encrypted = rsa.encrypt(generatedKeyPair.public, plaintext);
    
        describe('generates 2048-bit public / private key pair', function() {
            it('should generate result with keySize, time, public and private keys', function() {
                assert.equal(generatedKeyPair.hasOwnProperty("keySize"), true);
                assert.equal(generatedKeyPair.hasOwnProperty("time"), true);
                assert.equal(generatedKeyPair.hasOwnProperty("public"), true);
                assert.equal(generatedKeyPair.hasOwnProperty("private"), true);
            });
        });
    
        describe('rsa.encrypt(publicKey, plaintext) != plaintext', function() {
            it('returns encrypted text different from plaintext', function() {
                assert.notEqual(encrypted, plaintext);
            });
        });
    
        describe('rsa.encrypt(publicKey, plaintext) updates each time', function() {
            it('returns re-encrypted text different from previous attempt', function() {
                assert.notEqual(rsa.encrypt(generatedKeyPair.public, plaintext), encrypted);
            });
        });
    
        describe('rsa.decrypt(privateKey, encrypted) == plaintext', function() {
            it('returns correctly decrypted plaintext', function() {
                assert.equal(rsa.decrypt(generatedKeyPair.private, encrypted), plaintext);
            });
        });
    });

    describe('asynchronously generated key pair tests', function(){
        it('should generate result with keySize, time, public and private keys within 10s', function(done) {
            this.timeout(10000);
            rsa.generateKeys(defaultKeySize, (error, generatedKeyPair) => {
                if (error) {
                    done(error);
                } else {
                    assert.equal(generatedKeyPair.hasOwnProperty("keySize"), true);
                    assert.equal(generatedKeyPair.hasOwnProperty("time"), true);
                    assert.equal(generatedKeyPair.hasOwnProperty("public"), true);
                    assert.equal(generatedKeyPair.hasOwnProperty("private"), true);
                    done();
                }
            });
        });
    });
});
