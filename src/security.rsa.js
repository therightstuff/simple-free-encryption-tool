const crypto = require('crypto');
const childProcess = require('child_process');
const keyGenerator = require('./keyGenerator');
const NodeRSA = require('node-rsa');
const path = require('path');

const KEY_GENERATOR_PATH = path.resolve(__dirname + '/keyGenerator.js');

let rsa = {
    INVALID_CALL_WITHOUT_KEYSIZE: 'generateKeys called without keySize argument',
    INVALID_CALL_WITH_INVALID_KEYSIZE: 'Key size must be a number and a multiple of 8.',

    // both parameters must be strings, publicKey PEM formatted
    encrypt: function (publicKey, message) {
        let buffer = Buffer.from(message);
        let encrypted = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
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
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            buffer
        );
        return decrypted.toString('utf8');
    },

    // generate PEM formatted public / private key pair asynchronously
    generateKeys: function (keySize, next) {
        // generateKeys will return a promise that resolves to the key pair,
        // and if a callback is provided, it will be called with the key pair
        return new Promise((resolve, reject) => {
                if (!keySize) {
                    if (next) {
                        next(new Error(rsa.INVALID_CALL_WITHOUT_KEYSIZE));
                    }
                    return reject(new Error(rsa.INVALID_CALL_WITHOUT_KEYSIZE));
                }
                // convert keySize to number or throw error if not a number
                keySize = Number(keySize);
                if (isNaN(keySize) || keySize % 8 !== 0) {
                    if (next) {
                        next(new Error(rsa.INVALID_CALL_WITH_INVALID_KEYSIZE));
                    }
                    return reject(new Error(rsa.INVALID_CALL_WITH_INVALID_KEYSIZE));
                }

                // spawn child keyGenerator process
                childProcess.execFile('node', [KEY_GENERATOR_PATH, keySize], function (error, stdout, stderr){
                    if (next) {
                        error ? next(error) : next(null, JSON.parse(stdout));
                    }
                    return error ? reject(error) : resolve(JSON.parse(stdout));
                });
        });
    },

    // generate PEM formatted public / private key pair synchronously
    generateKeysSync: function(keySize){
        if (!keySize) {
            throw new Error(rsa.INVALID_CALL_WITHOUT_KEYSIZE);
        }
        // convert keySize to number or throw error if not a number
        keySize = Number(keySize);
        if (isNaN(keySize) || keySize % 8 !== 0) {
            throw new Error(rsa.INVALID_CALL_WITH_INVALID_KEYSIZE);
        }
        return keyGenerator(keySize);
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
