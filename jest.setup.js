// Expose Node.js globals that jsdom doesn't include in its sandbox
const { TextEncoder, TextDecoder } = require('node:util');
globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;

// Expose Node.js Web Crypto API (available in Node 20+)
const { webcrypto } = require('node:crypto');
globalThis.crypto = webcrypto;
