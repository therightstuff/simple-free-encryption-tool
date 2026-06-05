const assert = require('node:assert');
const utils = require('../src/utils');

describe('utils', function() {
    describe('randomstring', function() {
        describe('generate uses options correctly', function() {
            it('generate returns 32-character (default) randomly generated string', async function() {
                let previousString = await utils.randomstring.generate();
                let currentString = await utils.randomstring.generate();
                assert.strictEqual(currentString.length, 32);
                assert.notStrictEqual(previousString, currentString);
            });

            it('generate returns 28-character randomly generated string using options', async function() {
                let previousString = await utils.randomstring.generate({ length: 28 });
                let currentString = await utils.randomstring.generate({ length: 28 });
                assert.strictEqual(currentString.length, 28);
                assert.notStrictEqual(previousString, currentString);
            });

            it('generate returns 30-character randomly generated string using option override', async function() {
                let previousString = await utils.randomstring.generate(30);
                let currentString = await utils.randomstring.generate(30);
                assert.strictEqual(currentString.length, 30);
                assert.notStrictEqual(previousString, currentString);
            });
        });

         describe('generateSync uses options correctly', function() {
            it('generateSync returns 32-character (default) randomly generated string', function() {
                let previousString = utils.randomstring.generateSync();
                let currentString = utils.randomstring.generateSync();
                assert.strictEqual(currentString.length, 32);
                assert.notStrictEqual(previousString, currentString);
            });

            it('generateSync returns 28-character randomly generated string using options', function() {
                let previousString = utils.randomstring.generateSync({ length: 28 });
                let currentString = utils.randomstring.generateSync({ length: 28 });
                assert.strictEqual(currentString.length, 28);
                assert.notStrictEqual(previousString, currentString);
            });

            it('generateSync returns 30-character randomly generated string using option override', function() {
                let previousString = utils.randomstring.generateSync(30);
                let currentString = utils.randomstring.generateSync(30);
                assert.strictEqual(currentString.length, 30);
                assert.notStrictEqual(previousString, currentString);
            });
        });
     });
});
