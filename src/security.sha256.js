let sha256 = {
    hash: async function (message) {
        if (message === undefined || message === null) {
            throw new TypeError('The "message" argument must be a string');
        }
        const encoded = new TextEncoder().encode(String(message));
        const buffer = await globalThis.crypto.subtle.digest('SHA-256', encoded);
        return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
};

module.exports = sha256;
