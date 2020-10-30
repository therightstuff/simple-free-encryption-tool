const assert = require('assert');
const sha256 = require('../src/security.sha256');

describe('sha256', function() {
    let plaintext = "plaintext";
    let expectedHash = "96d62e2abd3e42de5f50330fb8efc4c5599835278077b21e9aa0b33c1df07a1c";

    describe('sha256.hash(plaintext) = expectedHash', function() {
        it('should return expected hash for plaintext', function() {
            assert.strictEqual(sha256.hash(plaintext), expectedHash);
        });
    });

    describe('sha256.hash() throws error', function() {
        it('throws an error on null value', function() {
            assert.throws(sha256.hash, TypeError, 'The "data" argument must be one of type string, Buffer, TypedArray, or DataView. Received type undefined');
        });
    });
});
