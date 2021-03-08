const assert = require('assert');
const rsa = require('../src/security.rsa');

describe('rsa', function() {
    let plaintext = "plaintext";
    let testKeySize = 2048;
    let keyGenerationTimeout = testKeySize * 10;

    describe('synchronously generated key pair tests', function(){
        let generatedKeyPair = rsa.generateKeysSync(testKeySize);
        let encrypted = rsa.encrypt(generatedKeyPair.public, plaintext);

        describe('generates 2048-bit public / private key pair', function() {
            it('should generate result with keySize, time, public and private keys', function() {
                assert.strictEqual(generatedKeyPair.hasOwnProperty("keySize"), true);
                assert.strictEqual(generatedKeyPair.hasOwnProperty("time"), true);
                assert.strictEqual(generatedKeyPair.hasOwnProperty("public"), true);
                assert.strictEqual(generatedKeyPair.hasOwnProperty("private"), true);
            });
            it('throws an error when no keySize argument provided', function(done) {
                let result = 'expected error, none thrown';
                try {
                    rsa.generateKeysSync();
                } catch(err) {
                    if (err.message === rsa.INVALID_CALL_WITHOUT_KEYSIZE) {
                        return done();
                    }
                    result = err;
                }
                return done(new Error(result));
            });
            it('resolves with an error when no keySize provided', function(done) {
                let result = 'expected error, none thrown';
                try {
                    rsa.generateKeysSync(null, (err) => {
                        if (err) {
                            if (err.message === rsa.INVALID_CALL_WITHOUT_KEYSIZE) {
                                return done();
                            }
                            return done(new Error(err));
                        }
                        return done(new Error(result));
                    });
                } catch(err) {
                    return done(err);
                }
            });
            it('throws an error when invalid keySize argument provided', function(done) {
                let result = 'expected error, none thrown';
                try {
                    rsa.generateKeysSync('asdf');
                } catch(err) {
                    if (err.message === rsa.INVALID_CALL_WITH_INVALID_KEYSIZE) {
                        return done();
                    }
                    result = err;
                }
                return done(new Error(result));
            });
            it('resolves with an error when invalid keySize provided', function(done) {
                let result = 'expected error, none thrown';
                try {
                    rsa.generateKeysSync('asdf', (err) => {
                        if (err) {
                            if (err.message === rsa.INVALID_CALL_WITH_INVALID_KEYSIZE) {
                                return done();
                            }
                            return done(new Error(err));
                        }
                        return done(new Error(result));
                    });
                } catch(err) {
                    return done(err);
                }
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
            this.timeout(keyGenerationTimeout);
            rsa.generateKeysSync(testKeySize, (error, generatedKeyPair) => {
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
                rsa.generateKeys();
            } catch(err) {
                if (err.message === rsa.INVALID_CALL_WITHOUT_CALLBACK) {
                    return done();
                }
                result = err;
            }
            return done(new Error(result));
        });
        it('resolves with an error when invalid keySize provided', function(done) {
            let result = 'expected error, none thrown';
            try {
                rsa.generateKeys(null, (err) => {
                    if (err) {
                        if (err.message.indexOf(rsa.INVALID_CALL_WITH_INVALID_KEYSIZE) > 0) {
                            return done();
                        }
                        return done(new Error(err));
                    }
                    return done(new Error(result));
                });
            } catch(err) {
                return done(err);
            }
        });
        it('resolves with an error when invalid keySize provided', function(done) {
            let result = 'expected error, none thrown';
            try {
                rsa.generateKeys('asdf', (err) => {
                    if (err) {
                        if (err.message.indexOf(rsa.INVALID_CALL_WITH_INVALID_KEYSIZE) > 0) {
                            return done();
                        }
                        return done(new Error(err));
                    }
                    return done(new Error(result));
                });
            } catch(err) {
                return done(err);
            }
        });
    });

    describe('asynchronously generated key pair tests', function(){
        it(`should generate result with keySize, time, public and private keys within ${keyGenerationTimeout}ms`, function(done) {
            this.timeout(keyGenerationTimeout);
            rsa.generateKeys(testKeySize, (error, generatedKeyPair) => {
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
                rsa.generateKeys(testKeySize);
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
