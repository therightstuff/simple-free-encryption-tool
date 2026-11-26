// v1 authenticates its format identifier and stores nonce || ciphertext || tag.
const format = 'sfet1';
const header = new TextEncoder().encode(format);
const nonceSize = 12;
const tagSize = 16;

async function generateKey({ extractable = false } = {}) {
    if (typeof extractable !== 'boolean') throw new TypeError('extractable must be a boolean');
    return globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt']);
}

function checkKey(key) {
    if (key?.algorithm?.name !== 'AES-GCM' || key.algorithm.length !== 256) {
        throw new TypeError('An AES-256-GCM CryptoKey is required');
    }
}

function parameters(iv) {
    return { name: 'AES-GCM', iv, additionalData: header, tagLength: tagSize * 8 };
}

function encode(bytes) {
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 8192) {
        binary += String.fromCodePoint(...bytes.subarray(offset, offset + 8192));
    }
    return btoa(binary);
}

async function seal(key, plaintext) {
    checkKey(key);
    if (typeof plaintext !== 'string') throw new TypeError('Plaintext must be a string');
    if (/[\uD800-\uDFFF]/u.test(plaintext)) throw new TypeError('Plaintext contains an unpaired surrogate');
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(nonceSize));
    const encrypted = await globalThis.crypto.subtle.encrypt(parameters(nonce), key, new TextEncoder().encode(plaintext));
    const payload = new Uint8Array(nonceSize + encrypted.byteLength);
    payload.set(nonce);
    payload.set(new Uint8Array(encrypted), nonceSize);
    return format + '.' + encode(payload);
}

function decodePayload(message) {
    if (typeof message !== 'string' || !message.startsWith(format + '.')) {
        throw new Error('Unsupported sealed message format');
    }
    const encoded = message.slice(format.length + 1);
    let binary;
    try {
        binary = atob(encoded);
    } catch {
        throw new Error('Invalid sealed message encoding');
    }
    if (binary.length < nonceSize + tagSize || btoa(binary) !== encoded) {
        throw new Error('Invalid sealed message encoding');
    }
    return Uint8Array.from(binary, char => char.codePointAt(0));
}

function extractIv(message) {
    return decodePayload(message).subarray(0, nonceSize);
}

function extractCiphertext(message) {
    return decodePayload(message).subarray(nonceSize, -tagSize);
}

function extractTag(message) {
    return decodePayload(message).subarray(-tagSize);
}

async function open(key, message) {
    checkKey(key);
    const payload = decodePayload(message);
    const decrypted = await globalThis.crypto.subtle.decrypt(
        parameters(payload.subarray(0, nonceSize)), key, payload.subarray(nonceSize)
    );
    return new TextDecoder('utf-8', { ignoreBOM: true }).decode(decrypted);
}

module.exports = { generateKey, seal, open, extractIv, extractCiphertext, extractTag };
