const assert = require('assert');
const md5 = require('../src/security.md5');

describe('md5', function() {
    var plaintext = "plaintext";
    var expectedHash = "f2bc5b1d869870d7688f71b2d87030bd";
      
    describe('md5.hash(plaintext) = expectedHash', function() {
        it('should return expected hash for plaintext', function() {
            assert.equal(md5.hash(plaintext), expectedHash);
        });
    });

    describe('md5.hash() throws error', function() {
        it('throws an error on null value', function() {
            assert.throws(() => {
                md5.hash();
            }, (err) => err.message === 'The "data" argument must be one of type string, Buffer, TypedArray, or DataView. Received type undefined')
        });
    });
});
