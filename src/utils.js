// randomstring replacement using Web Crypto — no Node.js dependencies,
// works identically in browsers and Node 20+.
const DEFAULT_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

const generate = function (options) {
    if (typeof options === 'number') {
        options = { length: options };
    }
    const opts = options || {};
    const length = opts.length || 32;
    const chars = opts.charset || DEFAULT_CHARSET;
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => chars[b % chars.length]).join('');
};

const randomstring = {
    generate: async function (options) {
        return generate(options);
    },
    generateSync: generate
};

module.exports = { randomstring };
