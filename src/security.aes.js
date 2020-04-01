var crypto = require('crypto');
var md5 = require('./security.md5');

var randomstring = require('randomstring');

// http://lollyrock.com/articles/nodejs-encryption/
// NOTE: aes-256-cbc is compatible with the .NET crypto package
var aes = {
    INVALID_IV_ERROR: "Invalid iv, 16-character string required",
    INVALID_KEY_ERROR: "Invalid key, 32-character string required",
    NULL_IV: "0000000000000000",
    algorithm: 'aes-256-cbc',
    encrypt: function (key, message, iv) {
        iv = iv || aes.NULL_IV;
        aes.validateKey(key);
        if (key.length != 32) key = md5.hash(key);
        aes.validateIv(iv);
        key = Buffer.from(key);
		var cipher = crypto.createCipheriv(aes.algorithm, key, iv);
        return cipher.update(message, 'utf8', 'base64') + cipher.final('base64');
	},

    decrypt: function (key, message, iv) {
        iv = iv || aes.NULL_IV;
        aes.validateKey(key);
        if (key.length != 32) key = md5.hash(key);
        aes.validateIv(iv);
        key = Buffer.from(key);
        var decipher = crypto.createDecipheriv(aes.algorithm, key, iv);
        return decipher.update(message, 'base64', 'utf8') + decipher.final('utf8');
    },

    generateIv: function () {
        // https://stackoverflow.com/a/42485606/2860309
        // output eg. 2f6c60343819c193
        return crypto.randomBytes(16).toString('hex').slice(0, 16);
    },
    validateIv: function(iv) {
        if (!iv || iv.length != 16) {
            throw new Error(aes.INVALID_IV_ERROR);
        }
    },
	generateKey: function () {
		return md5.hash(randomstring.generate());
    },
    validateKey: function(key) {
        if (!key) {
            throw new Error(aes.INVALID_KEY_ERROR);
        }
    }
};

module.exports = aes;