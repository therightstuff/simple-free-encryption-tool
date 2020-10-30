const assert = require('assert');
const rsa = require('../src/security.rsa');

describe('rsa', function() {
    let plaintext = "plaintext";
    let defaultKeySize = 2048;

    describe('synchronously generated key pair tests', function(){
        let generatedKeyPair = rsa.generateKeysSync();
        let encrypted = rsa.encrypt(generatedKeyPair.public, plaintext);

        describe('generates 2048-bit public / private key pair', function() {
            it('should generate result with keySize, time, public and private keys', function() {
                assert.strictEqual(generatedKeyPair.hasOwnProperty("keySize"), true);
                assert.strictEqual(generatedKeyPair.hasOwnProperty("time"), true);
                assert.strictEqual(generatedKeyPair.hasOwnProperty("public"), true);
                assert.strictEqual(generatedKeyPair.hasOwnProperty("private"), true);
            });
        });

        describe('rsa.encrypt(publicKey, plaintext) != plaintext', function() {
            it('returns encrypted text different from plaintext', function() {
                assert.notStrictEqual(encrypted, plaintext);
            });
        });

        describe('rsa.encrypt(publicKey, plaintext) updates each time', function() {
            it('returns re-encrypted text different from previous attempt', function() {
                assert.notStrictEqual(rsa.encrypt(generatedKeyPair.public, plaintext), encrypted);
            });
        });

        describe('rsa.decrypt(privateKey, encrypted) == plaintext', function() {
            it('returns correctly decrypted plaintext', function() {
                assert.strictEqual(rsa.decrypt(generatedKeyPair.private, encrypted), plaintext);
            });
        });

        describe('rsa.sign and rsa.verify are symmetric', function() {
            it('returns whether signature is verified', function() {
                assert.strictEqual(
                    rsa.verify(
                        generatedKeyPair.public,
                        plaintext,
                        rsa.sign(generatedKeyPair.private, plaintext)
                    ),
                    true
                )
            });
        });
    });

    describe('callback for synchronously generated key pair tests', function(){
        it('should generate result with keySize, time, public and private keys', function(done) {
            this.timeout(10000);
            rsa.generateKeysSync(defaultKeySize, (error, generatedKeyPair) => {
                if (error) {
                    done(error);
                } else {
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("keySize"), true);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("time"), true);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("public"), true);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("private"), true);
                    done();
                }
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
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("keySize"), true);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("time"), true);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("public"), true);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("private"), true);
                    done();
                }
            });
        });
        it('throws an error when no callback function provided', function(done) {
            let result = 'expected error, none thrown';
            try {
                rsa.generateKeys(defaultKeySize);
            } catch(err) {
                if (err.message === rsa.INVALID_CALL_WITHOUT_CALLBACK) {
                    return done();
                }
                result = err;
            }
            return done(new Error(result));
        });
    });
});
