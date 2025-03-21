const crypto = require('crypto');
// NOTE: at present there is no way to browserify the crypto module, otherwise we
//       could use the crypto module's generateKeyPair methods
//       see https://medium.com/@yuvrajkakkar1/crypto-nodejs-encryption-issue-rsa-padding-add-pkcs1-type-1-data-too-large-for-key-size-e5e8a52ce8fc
const NodeRSA = require('node-rsa');

function generateKeysSync(keySize) {
    if (!keySize) {
        throw new Error(rsa.INVALID_CALL_WITHOUT_KEYSIZE);
    }
    // convert keySize to number or throw error if not a number
    keySize = Number(keySize);
    if (isNaN(keySize) || keySize % 8 !== 0) {
        throw new Error(rsa.INVALID_CALL_WITH_INVALID_KEYSIZE);
    }
    const startTime = new Date().getTime();
    let key = new NodeRSA({ b: keySize });
    const endTime = new Date().getTime();

    return {
        'keySize': keySize,
        'time': endTime - startTime,
        'private': key.exportKey('pkcs1-private-pem'),
        'public': key.exportKey('pkcs8-public-pem')
    };
}

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
        return new Promise((resolve, reject) => {
            try {
                const keys = generateKeysSync(keySize);
                if (next) {
                    next(null, keys);
                }
                return resolve(keys);
            } catch (error) {
                if (next) {
                    next(error);
                }
                return reject(error);
            }
        });
    },

    generateKeysSync: generateKeysSync,

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
