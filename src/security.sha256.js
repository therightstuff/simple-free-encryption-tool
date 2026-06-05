// js-sha256 provides pure-JavaScript SHA-256 hashing for cross-platform sync operations.
// Works in both Node.js and browser contexts.
const sha256 = require('js-sha256');

// Shared synchronous hash implementation using pure-JS SHA-256.
// Available in all runtimes (Node.js and browsers).
const hash = function (message) {
    if (message === undefined || message === null) {
        throw new TypeError('The "message" argument must be a string');
    }
    return sha256(String(message));
};

module.exports = {
    hash: async function (message) {
        if (message === undefined || message === null) {
            throw new TypeError('The "message" argument must be a string');
        }
        // Use native Web Crypto API for async when available (more efficient).
        const encoded = new TextEncoder().encode(String(message));
        const buffer = await globalThis.crypto.subtle.digest('SHA-256', encoded);
        return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    },
    hashSync: hash
};
