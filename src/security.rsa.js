const crypto = require('crypto');
const childProcess = require('child_process');
const keyGenerator = require('./keyGenerator');
const NodeRSA = require('node-rsa');
const path = require('path');

let rsa = {
    INVALID_CALL_WITHOUT_KEYSIZE: 'generateKeys called without keySize argument',
    INVALID_CALL_WITH_INVALID_KEYSIZE: 'Key size must be a multiple of 8.',
    INVALID_CALL_WITHOUT_CALLBACK: 'generateKeys called without callback function',

    // both parameters must be strings, publicKey PEM formatted
    encrypt: function (publicKey, message) {
        let buffer = Buffer.from(message);
        let encrypted = crypto.publicEncrypt(
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
        let buffer = Buffer.from(message, 'base64');
        let decrypted = crypto.privateDecrypt(
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
            throw new Error(rsa.INVALID_CALL_WITHOUT_CALLBACK);
        }
        // spawn child keyGenerator process, forward results to next
        let command = path.resolve(__dirname + '/keyGenerator.js');
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
        try {
            let generatedKeys = keyGenerator(keySize);
            if (next){
                next(null, generatedKeys);
            }
            return generatedKeys;
        } catch(err) {
            if (next) {
                return next(err);
            }
            throw err;
        }
    },

    sign: function(privateKey, message) {
        let key = new NodeRSA(privateKey);
        return key.sign(message).toString('base64');
    },

    verify: function(publicKey, message, signature) {
        let key = new NodeRSA(publicKey);
        return key.verify(message, Buffer.from(signature, 'base64'));
    }
};

module.exports = rsa;