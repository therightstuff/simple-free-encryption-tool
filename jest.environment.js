const JsdomEnvironment = require('jest-environment-jsdom').default;
const { webcrypto } = require('node:crypto');

class CustomEnvironment extends JsdomEnvironment {
    async setup() {
        await super.setup();
        // jsdom exposes a crypto object but without subtle (Web Crypto API).
        // Replace it with Node's webcrypto which has full crypto.subtle support.
        Object.defineProperty(this.global, 'crypto', {
            configurable: true,
            enumerable: true,
            writable: true,
            value: webcrypto
        });
        // Ensure btoa/atob are available (jsdom provides them, but confirm here)
        if (!this.global.btoa) {
            this.global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
            this.global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
        }
    }
}

module.exports = CustomEnvironment;
