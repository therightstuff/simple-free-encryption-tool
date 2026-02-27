const crypto = require('crypto');
const md5 = require('./security.md5');
const utils = require('./utils');

const INVALID_IV_ERROR = "Invalid iv, 16-character string required";
const INVALID_KEY_ERROR = "Invalid key, 32-character string required";
const INVALID_GCM_NONCE_ERROR = "Invalid nonce, 12-character string required";
const NULL_IV = "0000000000000000";


const cbc = {
    INVALID_IV_ERROR: INVALID_IV_ERROR,
    INVALID_KEY_ERROR: INVALID_KEY_ERROR,
    NULL_IV: NULL_IV,

    algorithm: 'aes-256-cbc',

    encrypt: function (key, message, iv) {
        iv = iv || cbc.NULL_IV;
        cbc.validateKey(key);
        cbc.validateIv(iv);
        key = Buffer.from(key);
		let cipher = crypto.createCipheriv(cbc.algorithm, key, iv);
        return cipher.update(message, 'utf8', 'base64') + cipher.final('base64');
	},

    decrypt: function (key, message, iv) {
        iv = iv || cbc.NULL_IV;
        cbc.validateKey(key);
        cbc.validateIv(iv);
        key = Buffer.from(key);
        let decipher = crypto.createDecipheriv(cbc.algorithm, key, iv);
        return decipher.update(message, 'base64', 'utf8') + decipher.final('utf8');
    },

    // generated IV must be a 16 character hexadecimal string
    generateIv: function () {
        // https://stackoverflow.com/a/42485606/2860309
        // output eg. 2f6c60343819c193
        return crypto.randomBytes(16).toString('hex').slice(0, 16);
    },

    validateIv: function(iv) {
        if (!iv || iv.length != 16) {
            throw new Error(cbc.INVALID_IV_ERROR);
        }
    },

    validateKey: function(key) {
        if (!key || key.length != 32) {
            throw new Error(cbc.INVALID_KEY_ERROR);
        }
    }
};

// AES-256-GCM: authenticated encryption with associated data (AEAD).
// encrypt() prepends the 16-byte auth tag to the ciphertext and returns a
// single base64 string, so the decrypt() signature mirrors cbc.
//
// IMPORTANT: a nonce MUST be provided and MUST be unique per (key, message)
// pair. Reusing a nonce with the same key catastrophically breaks both
// confidentiality and the authentication tag. Use gcm.generateNonce() to
// produce a fresh nonce for every encryption operation.
const gcm = {
    INVALID_KEY_ERROR: INVALID_KEY_ERROR,
    INVALID_NONCE_ERROR: INVALID_GCM_NONCE_ERROR,

    algorithm: 'aes-256-gcm',

    encrypt: function (key, message, nonce) {
        gcm.validateKey(key);
        gcm.validateNonce(nonce);
        key = Buffer.from(key);
        let cipher = crypto.createCipheriv(gcm.algorithm, key, nonce);
        let encrypted = Buffer.concat([
            cipher.update(message, 'utf8'),
            cipher.final()
        ]);
        let tag = cipher.getAuthTag(); // 16 bytes
        return Buffer.concat([tag, encrypted]).toString('base64');
    },

    decrypt: function (key, message, nonce) {
        gcm.validateKey(key);
        gcm.validateNonce(nonce);
        key = Buffer.from(key);
        let combined = Buffer.from(message, 'base64');
        let tag = combined.subarray(0, 16);
        let ciphertext = combined.subarray(16);
        let decipher = crypto.createDecipheriv(gcm.algorithm, key, nonce);
        decipher.setAuthTag(tag);
        return decipher.update(ciphertext, null, 'utf8') + decipher.final('utf8');
    },

    // generate a cryptographically random 12-byte nonce (NIST SP 800-38D recommended size).
    // a new nonce MUST be generated for every encryption operation with the same key.
    generateNonce: function () {
        return crypto.randomBytes(12).toString('hex').slice(0, 12);
    },

    validateNonce: function (nonce) {
        if (!nonce || nonce.length != 12) {
            throw new Error(gcm.INVALID_NONCE_ERROR);
        }
    },

    validateKey: function (key) {
        if (!key || key.length != 32) {
            throw new Error(gcm.INVALID_KEY_ERROR);
        }
    }
};

// http://lollyrock.com/articles/nodejs-encryption/
// NOTE: aes-256-cbc is compatible with the .NET crypto package
let aes = {
    INVALID_IV_ERROR: INVALID_IV_ERROR,
    INVALID_KEY_ERROR: INVALID_KEY_ERROR,
    INVALID_GCM_NONCE_ERROR: INVALID_GCM_NONCE_ERROR,
    NULL_IV: NULL_IV,

    cbc,
    gcm,

    // for backward compatibility, but use cbc.algorithm instead
    algorithm: cbc.algorithm,

    encrypt: (key, message, iv) => {
        console.warn("aes.encrypt is deprecated, use aes.cbc.encrypt with hashed key instead");
        aes.validateKey(key);
        return cbc.encrypt(md5.hash(key), message, iv);
    },
    decrypt: (key, message, iv) => {
        console.warn("aes.decrypt is deprecated, use aes.cbc.decrypt with hashed key instead");
        aes.validateKey(key);
        return cbc.decrypt(md5.hash(key), message, iv);
    },
    generateIv: () => {
        console.warn("aes.generateIv is deprecated, use aes.cbc.generateIv instead");
        return cbc.generateIv();
    },

    validateIv: (iv) => {
        console.warn("aes.validateIv is deprecated, use aes.cbc.validateIv instead");
        return cbc.validateIv(iv);
    },

    // DEPRECATED: use sfet.utils.randomstring directly instead,
    // no need to hash the result as hashing performed implicitly
    // by encrypt / decrypt
	generateKey: function () {
        console.warn("aes.generateKey is deprecated, use sfet.utils.randomstring directly instead");
		return md5.hash(utils.randomstring.generate());
    },
    validateKey: function(key) {
        console.warn("aes.validateKey is deprecated, use aes.cbc.validateKey instead");
        if (!key) {
            throw new Error(INVALID_KEY_ERROR);
        }
        if (key.length != 32) {
            console.warn("Warning: key length must be 32 characters, this will fail when using the updated methods. Deprecated methods use md5 hashing inherently");
        }
    }
};

module.exports = aes;
