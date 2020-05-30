const assert = require('assert');
const utils = require('../src/utils');

describe('utils', function() {
    describe('randomstring uses options correctly', function() {
        it('returns 32-character (default) randomly generated string', function() {
            let previousString = utils.randomstring.generate();
            let currentString = utils.randomstring.generate();
            assert.equal(currentString.length, 32);
            assert.notEqual(previousString, currentString);
        });

        it('returns 28-character randomly generated string using options', function() {
            let previousString = utils.randomstring.generate({ length: 28 });
            let currentString = utils.randomstring.generate({ length: 28 });
            assert.equal(currentString.length, 28);
            assert.notEqual(previousString, currentString);
        });

        it('returns 30-character randomly generated string using option override', function() {
            let previousString = utils.randomstring.generate(30);
            let currentString = utils.randomstring.generate(30);
            assert.equal(currentString.length, 30);
            assert.notEqual(previousString, currentString);
        });
    });
});
