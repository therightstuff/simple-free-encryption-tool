var crypto = require('crypto');
var childProcess = require('child_process');
var keyGenerator = require('./keyGenerator');
var path = require('path');

var rsa = {
    // both parameters must be strings, publicKey PEM formatted
    encrypt: function (publicKey, message) {
        var buffer = new Buffer(message);
        encrypted = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            },
            buffer
        );
        return encrypted.toString('base64');
    },

    // both parameters must be strings, publicKey PEM formatted
    decrypt: function (privateKey, message) {
        var buffer = new Buffer(message, 'base64');
        var decrypted = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            },
            buffer
        );
        return decrypted.toString('utf8');
    },

    // generate PEM formatted public / private key pair asynchronously
    // (not available on web client)
    generateKeys: function (keySize, next) {
        if (!next){
            throw new Error('generateKeys called without callback function');
        }
        // spawn child keyGenerator process, forward results to next
        var command = path.resolve(__dirname + '/keyGenerator.js');
        childProcess.execFile('node', [command, keySize], function (error, stdout, stderr){
            if (error){
                next(error);
            } else {
                next(error, JSON.parse(stdout));
            }
        });
    },

    // generate PEM formatted public / private key pair synchronously
    generateKeysSync: function(keySize, next){
        var generatedKeys = keyGenerator(keySize);
        if (next){
            next(null, generatedKeys);
        }
        return generatedKeys;
    }
};

module.exports = rsa;