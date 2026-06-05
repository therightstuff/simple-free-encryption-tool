const assert = require('node:assert');
const md5 = require('../src/security.md5');

describe('md5', function() {
    let plaintext = "plaintext";
    let expectedHash = "f2bc5b1d869870d7688f71b2d87030bd";

    describe('md5.hash(plaintext) = expectedHash', function() {
        it('should return expected hash for plaintext', async function() {
            assert.strictEqual(await md5.hash(plaintext), expectedHash);
        });
    });

    describe('md5.hashSync(plaintext) = expectedHash', function() {
        it('should return expected hash for plaintext', function() {
            assert.strictEqual(md5.hashSync(plaintext), expectedHash);
        });
    });

    describe('md5.hash() throws error', function() {
        it('throws an error on undefined value', async function() {
            await assert.rejects(() => md5.hash(), (err) => err.message === 'Illegal argument undefined');
        });

        it('throws an error on null value', async function() {
            await assert.rejects(() => md5.hash(null), (err) => err.message === 'Illegal argument undefined');
        });
    });

    describe('md5.hashSync() throws error', function() {
        it('throws an error on undefined value', function() {
            assert.throws(() => md5.hashSync(), (err) => err.message === 'Illegal argument undefined');
        });

        it('throws an error on null value', function() {
            assert.throws(() => md5.hashSync(null), (err) => err.message === 'Illegal argument undefined');
        });
    });
});
