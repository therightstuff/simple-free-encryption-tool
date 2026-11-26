const INVALID_IV_ERROR = "Invalid iv, 32 hex digits or a legacy 16-character string required";
const INVALID_KEY_ERROR = "Invalid key, 32-character string required";
const INVALID_GCM_NONCE_ERROR = "Invalid nonce, 24 hex digits or a legacy 12-character string required";
const NULL_IV = "0000000000000000";


function randomHex(byteLength) {
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(byteLength));
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Older versions passed fixed-length strings to Web Crypto as UTF-8.
function parameterBytes(value, legacyLength) {
    if (value.length === legacyLength) return new TextEncoder().encode(value);
    return Uint8Array.from(value.match(/../g), pair => Number.parseInt(pair, 16));
}

const cbc = {
    INVALID_IV_ERROR: INVALID_IV_ERROR,
    INVALID_KEY_ERROR: INVALID_KEY_ERROR,
    NULL_IV: NULL_IV,

    algorithm: 'AES-CBC',

    encrypt: async function (key, message, iv) {
        cbc.validateKey(key);
        cbc.validateIv(iv);
        if (message === null || message === undefined) {
            throw new TypeError('The "data" argument must be a string');
        }
        const keyBytes = new TextEncoder().encode(key);
        const ivBytes = parameterBytes(iv, 16);
        const cryptoKey = await globalThis.crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']
        );
        const msgBytes = new TextEncoder().encode(message);
        const encrypted = await globalThis.crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: ivBytes }, cryptoKey, msgBytes
        );
        return btoa(String.fromCodePoint(...new Uint8Array(encrypted)));
    },

    decrypt: async function (key, message, iv) {
        if (!iv) {
            console.warn('Legacy AES-CBC decryption without an IV uses a fixed IV. The security of this ciphertext is not guaranteed.');
            iv = NULL_IV;
        }
        cbc.validateKey(key);
        cbc.validateIv(iv);
        const keyBytes = new TextEncoder().encode(key);
        const ivBytes = parameterBytes(iv, 16);
        const cryptoKey = await globalThis.crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']
        );
        let msgBytes;
        try {
            msgBytes = Uint8Array.from(atob(message), c => c.codePointAt(0));
        } catch (err) {
            throw new Error(err.message || 'AES-CBC decryption failed (invalid ciphertext)');
        }
        const decrypted = await globalThis.crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: ivBytes }, cryptoKey, msgBytes
        );
        return new TextDecoder().decode(decrypted);
    },

    generateIv: function () {
        return randomHex(16);
    },

    validateIv: function(iv) {
        if (typeof iv !== 'string' || (iv.length !== 16 && !/^[0-9a-f]{32}$/i.test(iv))) {
            throw new Error(cbc.INVALID_IV_ERROR);
        }
    },

    validateKey: function(key) {
        if (key?.length != 32) {
            throw new Error(cbc.INVALID_KEY_ERROR);
        }
    }
};

// AES-256-GCM: authenticated encryption with associated data (AEAD).
// encrypt() returns a base64 string of the ciphertext with the 16-byte auth
// tag appended (Web Crypto appends the tag automatically).
//
// IMPORTANT: a nonce MUST be provided and MUST be unique per (key, message)
// pair. Reusing a nonce with the same key catastrophically breaks both
// confidentiality and the authentication tag. Use gcm.generateNonce() to
// produce a fresh nonce for every encryption operation.
const gcm = {
    INVALID_KEY_ERROR: INVALID_KEY_ERROR,
    INVALID_NONCE_ERROR: INVALID_GCM_NONCE_ERROR,

    algorithm: 'AES-GCM',

    encrypt: async function (key, message, nonce) {
        gcm.validateKey(key);
        gcm.validateNonce(nonce);
        if (message === null || message === undefined) {
            throw new TypeError('The "data" argument must be a string');
        }
        const keyBytes = new TextEncoder().encode(key);
        const nonceBytes = parameterBytes(nonce, 12);
        const cryptoKey = await globalThis.crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const msgBytes = new TextEncoder().encode(message);
        const encrypted = await globalThis.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 }, cryptoKey, msgBytes
        );
        return btoa(String.fromCodePoint(...new Uint8Array(encrypted)));
    },

    decrypt: async function (key, message, nonce) {
        gcm.validateKey(key);
        gcm.validateNonce(nonce);
        const keyBytes = new TextEncoder().encode(key);
        const nonceBytes = parameterBytes(nonce, 12);
        const cryptoKey = await globalThis.crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
        );
        let msgBytes;
        try {
            msgBytes = Uint8Array.from(atob(message), c => c.codePointAt(0));
        } catch (err) {
            throw new Error(err.message || 'AES-GCM decryption failed (invalid ciphertext)');
        }
        try {
            const decrypted = await globalThis.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 }, cryptoKey, msgBytes
            );
            return new TextDecoder().decode(decrypted);
        } catch (err) {
            throw new Error(err.message || 'AES-GCM decryption failed (authentication error)');
        }
    },

    generateNonce: function () {
        return randomHex(12);
    },

    validateNonce: function (nonce) {
        if (typeof nonce !== 'string' || (nonce.length !== 12 && !/^[0-9a-f]{24}$/i.test(nonce))) {
            throw new Error(gcm.INVALID_NONCE_ERROR);
        }
    },

    validateKey: function (key) {
        if (key?.length != 32) {
            throw new Error(gcm.INVALID_KEY_ERROR);
        }
    }
};

module.exports = { ...require('./sealed-message'), cbc, gcm };
