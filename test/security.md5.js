const assert = require('assert');
const md5 = require('../src/security.md5');

describe('md5', function() {
    let plaintext = "plaintext";
    let expectedHash = "f2bc5b1d869870d7688f71b2d87030bd";

    describe('md5.hash(plaintext) = expectedHash', function() {
        it('should return expected hash for plaintext', function() {
            assert.strictEqual(md5.hash(plaintext), expectedHash);
        });
    });

    describe('md5.hash() throws error', function() {
        it('throws an error on null value', function() {
            assert.throws(md5.hash, TypeError, 'The "data" argument must be one of type string, Buffer, TypedArray, or DataView. Received type undefined');
        });
    });
});
