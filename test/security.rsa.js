const assert = require('assert');
const rsa = require('../src/security.rsa');

describe('rsa', function() {
    const plaintext = "plaintext";
    const testKeySize = 2048;
    const keyGenerationTimeout = testKeySize * 10;

    describe('rsa methods work correctly with generated key pair', function() {
        this.timeout(keyGenerationTimeout);
        const generatedKeyPair = rsa.generateKeysSync(testKeySize);
        const encrypted = rsa.encrypt(generatedKeyPair.public, plaintext);

        it(`synchronously generated keys produced within ${keyGenerationTimeout}ms`, function() {
            assert.strictEqual(generatedKeyPair.time < keyGenerationTimeout, true);
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

    describe('synchronously generated key pair tests', function(){
        this.timeout(keyGenerationTimeout);
        it('should generate result with keySize, time, public and private keys', function(done) {
            try {
                const keys = rsa.generateKeysSync(testKeySize);
                assert.strictEqual(keys.hasOwnProperty("keySize"), true);
                assert.strictEqual(keys.keySize, testKeySize);
                assert.strictEqual(keys.hasOwnProperty("time"), true);
                assert.strictEqual(keys.time < keyGenerationTimeout, true);
                assert.strictEqual(keys.hasOwnProperty("public"), true);
                assert.strictEqual(keys.hasOwnProperty("private"), true);
                done();
            } catch(err) {
                done(err);
            }
        });
        it('throws an error when no keySize argument provided', function(done) {
            try {
                rsa.generateKeysSync();
                return done(new Error('expected error, none thrown'));
            } catch(err) {
                if (err.message === rsa.INVALID_CALL_WITHOUT_KEYSIZE) {
                    return done();
                }
                return done(new Error(err));
            }
        });
        it('resolves with an error when no keySize provided', function(done) {
            try {
                rsa.generateKeysSync(null);
                return done(new Error('expected error, none thrown'));
            } catch(err) {
                if (err.message === rsa.INVALID_CALL_WITHOUT_KEYSIZE) {
                    return done();
                }
                return done(new Error(err));
            }
        });
        it('throws an error when invalid keySize argument provided', function() {
            try {
                rsa.generateKeysSync('asdf');
                throw new Error('expected error, none thrown');
            } catch(err) {
                if (err.message === rsa.INVALID_CALL_WITH_INVALID_KEYSIZE) {
                    return;
                }
                throw err;
            }
        });
    });

    describe('asynchronously generated key pair tests', function(){
        this.timeout(keyGenerationTimeout);
        it(`(async) should generate result with keySize, time, public and private keys within ${keyGenerationTimeout}ms`, async function() {
            const generatedKeyPair = await rsa.generateKeys(testKeySize);
            assert.strictEqual(generatedKeyPair.hasOwnProperty("keySize"), true);
            assert.strictEqual(generatedKeyPair.keySize, testKeySize);
            assert.strictEqual(generatedKeyPair.hasOwnProperty("time"), true);
            assert.strictEqual(generatedKeyPair.hasOwnProperty("public"), true);
            assert.strictEqual(generatedKeyPair.hasOwnProperty("private"), true);
        });
        it(`(callback) should generate result with keySize, time, public and private keys within ${keyGenerationTimeout}ms`, function(done) {
            rsa.generateKeys(testKeySize, (err, generatedKeyPair) => {
                if (err) {
                    done(err);
                } else {
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("keySize"), true);
                    assert.strictEqual(generatedKeyPair.keySize, testKeySize);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("time"), true);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("public"), true);
                    assert.strictEqual(generatedKeyPair.hasOwnProperty("private"), true);
                    done();
                }
            });
        });
        it('(async) throws an error when no keySize provided', async function() {
            try {
                await rsa.generateKeys();
                throw new Error('expected error, none thrown');
            } catch(err) {
                if (err.message === rsa.INVALID_CALL_WITHOUT_KEYSIZE) {
                    return;
                }
                throw err;
            }
        });
        it('(callback) throws an error when no keySize provided', async function(done) {
            rsa.generateKeys(null, (err, result) => {
                if (err) {
                    if (err.message === rsa.INVALID_CALL_WITHOUT_KEYSIZE) {
                        return done();
                    }
                    return done(err);
                }
                return done(new Error('expected error, none thrown'));
            });
        });
        it('(async) resolves with an error when invalid keySize provided', async function() {
            try {
                await rsa.generateKeys('asdf');
                throw new Error('expected error, none thrown');
            } catch(err) {
                if (err.message === rsa.INVALID_CALL_WITH_INVALID_KEYSIZE) {
                    return;
                }
                throw err;
            }
        });
        it('(callback) resolves with an error when invalid keySize provided', function(done) {
            rsa.generateKeys('asdf', (err, result) => {
                if (err) {
                    if (err.message === rsa.INVALID_CALL_WITH_INVALID_KEYSIZE) {
                        return done();
                    }
                    return done(err);
                }
                return done(new Error('expected error, none thrown'));
            });
        });
    });
});
