const assert = require('node:assert');
const rsa = require('../src/security.rsa');

describe('rsa', function() {
    const plaintext = "plaintext";
    const testKeySize = 2048;
    const keyGenerationTimeout = testKeySize * 10;
    jest.setTimeout(keyGenerationTimeout + 5000);

    describe('rsa methods work correctly with generated key pair', function() {
        let generatedKeyPair;
        let encrypted;

        beforeAll(async function() {
            generatedKeyPair = await rsa.generateKeys(testKeySize);
            encrypted = await rsa.encrypt(generatedKeyPair.public, plaintext);
        });

        describe('rsa.encrypt(publicKey, plaintext) != plaintext', function() {
            it('returns encrypted text different from plaintext', function() {
                assert.notStrictEqual(encrypted, plaintext);
            });
        });

        describe('rsa.encrypt(publicKey, plaintext) updates each time', function() {
            it('returns re-encrypted text different from previous attempt', async function() {
                assert.notStrictEqual(await rsa.encrypt(generatedKeyPair.public, plaintext), encrypted);
            });
        });

        describe('rsa.decrypt(privateKey, encrypted) == plaintext', function() {
            it('returns correctly decrypted plaintext', async function() {
                assert.strictEqual(await rsa.decrypt(generatedKeyPair.private, encrypted), plaintext);
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

    describe('asynchronously generated key pair tests', function(){
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
        it('(callback) throws an error when no keySize provided', function(done) {
            rsa.generateKeys(null, (err, result) => {
                if (err) {
                    if (err.message === rsa.INVALID_CALL_WITHOUT_KEYSIZE) {
                        return done();
                    }
                    return done(err);
                }
                return done(new Error('expected error, none thrown'));
            }).catch(() => {}); // error already handled by callback
        });
        it('(async) throws an error when no keySize provided', function() {
            return rsa.generateKeys(null).catch(err => {
                assert.strictEqual(err.message, rsa.INVALID_CALL_WITHOUT_KEYSIZE);
            });
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
            }).catch(() => {}); // error already handled by callback
        });
        it('(async) resolves with an error when invalid keySize provided', function() {
            return rsa.generateKeys('asdf').catch(err => {
                assert.strictEqual(err.message, rsa.INVALID_CALL_WITH_INVALID_KEYSIZE);
            });
        });
    });
});
