const NodeRSA = require('node-rsa').default;

let rsa = {
    INVALID_CALL_WITHOUT_KEYSIZE: 'generateKeys called without keySize argument',
    INVALID_CALL_WITH_INVALID_KEYSIZE: 'Key size must be a number and a multiple of 8.',

    // both parameters must be strings, publicKey PEM formatted
    encrypt: async function (publicKey, message) {
        const keyObj = await globalThis.crypto.subtle.importKey(
            'spki',
            pemToDer(publicKey),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );
        const msgBytes = new TextEncoder().encode(message);
        const encrypted = await globalThis.crypto.subtle.encrypt(
            { name: 'RSA-OAEP' }, keyObj, msgBytes
        );
        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    },

    // both parameters must be strings, privateKey PEM formatted
    decrypt: async function (privateKey, message) {
        const keyObj = await globalThis.crypto.subtle.importKey(
            'pkcs8',
            pemToDer(privateKey),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['decrypt']
        );
        const msgBytes = Uint8Array.from(atob(message), c => c.charCodeAt(0));
        const decrypted = await globalThis.crypto.subtle.decrypt(
            { name: 'RSA-OAEP' }, keyObj, msgBytes
        );
        return new TextDecoder().decode(decrypted);
    },

    // generate PEM formatted public / private key pair asynchronously
    generateKeys: function (keySize, next) {
        return new Promise((resolve, reject) => {
            try {
                if (!keySize) {
                    throw new Error(rsa.INVALID_CALL_WITHOUT_KEYSIZE);
                }
                keySize = Number(keySize);
                if (isNaN(keySize) || keySize % 8 !== 0) {
                    throw new Error(rsa.INVALID_CALL_WITH_INVALID_KEYSIZE);
                }
                const startTime = new Date().getTime();
                let key = new NodeRSA({ b: keySize });
                const endTime = new Date().getTime();
                const keys = {
                    keySize: keySize,
                    time: endTime - startTime,
                    private: key.exportKey('pkcs8-private-pem'),
                    public: key.exportKey('pkcs8-public-pem')
                };
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

    sign: function(privateKey, message) {
        let key = new NodeRSA(privateKey);
        return key.sign(message, 'base64');
    },

    verify: function(publicKey, message, signature) {
        let key = new NodeRSA(publicKey);
        return key.verify(message, signature, 'utf8', 'base64');
    }
};

function pemToDer(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

module.exports = rsa;
