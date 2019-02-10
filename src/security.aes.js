var crypto = require('crypto');
var md5 = require('./security.md5');

var randomstring = require('randomstring');

// http://lollyrock.com/articles/nodejs-encryption/
// NOTE: aes-256-cbc is compatible with the .NET crypto package
var aes = {
    algorithm: 'aes-256-cbc',
    encrypt: function (key, message) {
		var cipher = crypto.createCipher(aes.algorithm, key);
        return cipher.update(message, 'utf8', 'base64') + cipher.final('base64');
	},

    decrypt: function (key, message) {
        var decipher = crypto.createDecipher(aes.algorithm, key);
        return decipher.update(message, 'base64', 'utf8') + decipher.final('utf8');
    },

	generateKey: function () {
		return md5.hash(randomstring.generate());
	}
};

module.exports = aes;