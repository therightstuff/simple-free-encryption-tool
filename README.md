# simple-free-encryption-tool

![Coverage Badge 100%](https://img.shields.io/badge/Coverage-100%25-83A603.svg?color=black&prefix=![](https://img.shields.io/badge/Coverage-100%25-83A603.svg?color=black&prefix=$coverage$))
[![Known Vulnerabilities](https://snyk.io/test/github/therightstuff/simple-free-encryption-tool/badge.svg)](https://snyk.io/test/github/therightstuff/simple-free-encryption-tool)

## Simple Free RSA / AES Encryption and Decryption

Simple Free Encryption Tool (sfet) uses RSA and AES versions that are strong and allow encryption between client-side Javascript and Node.js.

**NOTE**: Originally this package provided compatibility with C# as well, but that's no longer officially supported. If you're interested in seeing what that looked like, refer to [v2.0.14](https://github.com/therightstuff/simple-free-encryption-tool/tree/v2.0.14)

Open and free for all to see, can be run stand-alone on a local machine for an extra sense of security; all functionality runs entirely locally once the page has been loaded.

Latest client version can be loaded directly from the [GitHub HTML preview](http://htmlpreview.github.io/?https://github.com/therightstuff/simple-free-encryption-tool/blob/master/dist/index.html).
As that service hasn't been working lately (due to CORS issues, apparently), I've also made it available on [industrialcuriosity.com](https://industrialcuriosity.com/sfet).

If you've found this tool useful, [please consider making a donation](https://www.industrialcuriosity.com/p/donate.html)!

## Encryption 101

RSA encryption operates on a very limited string length, it is generally used to asymmetrically encrypt a shared secret that in turn is used for symmetric encryption. The standard use-case is to generate a random shared secret and transmit it encrypted with the destination's public RSA key. Once the destination has decrypted the shared secret with its private RSA key both sides will be able to use that secret to encrypt and decrypt communication with AES.

Signing a message to prove authorship (and that it hasn't been tampered with) is performed on the plaintext message, and the resulting signature can only be verified with the public key matching the private key it was signed with. The padding for signing and verifying signatures is not the same as for encrypting and decrypting messages.

## AES Variants

AES (Advanced Encryption Standard) comes in several variants based on **key size** and **mode of operation**:

**Key sizes:**

- **AES-128** – 128-bit key; fast and still considered secure for most purposes.
- **AES-192** – 192-bit key; rarely used in practice.
- **AES-256** – 256-bit key; strongest option, preferred when maximum security is required.

**Common modes:**

- **ECB** (Electronic Codebook) – encrypts each block independently with no IV; identical plaintext blocks produce identical ciphertext blocks, making patterns visible. Generally considered insecure for anything beyond trivial use.
- **CBC** (Cipher Block Chaining) – each block is XOR'd with the previous ciphertext block before encryption, requiring an IV for the first block. Widely used and well-understood; provides strong confidentiality when a unique IV is used per message.
- **CTR** (Counter) – turns AES into a stream cipher by encrypting a counter value and XOR'ing it with plaintext; parallelizable and efficient but provides no built-in authentication.
- **GCM** (Galois/Counter Mode) – extends CTR with an authentication tag, providing both confidentiality and integrity in a single pass. The modern recommended default for most applications. GCM uses a **12-byte nonce** (rather than CBC's 16-byte IV); reusing a nonce with the same key is catastrophic — it breaks both confidentiality and the authentication tag, potentially allowing key recovery.

**This repository implements AES-256-CBC and AES-256-GCM** — both use 256-bit keys (an exactly 32-character string). CBC uses a 16-character IV; GCM uses a 12-character nonce. For new code, prefer `aes.gcm` — it provides authenticated encryption and will detect tampering.

## Important Notes

### AES API: `aes.cbc` and `aes.gcm`

The top-level `aes.*` methods (`aes.encrypt`, `aes.decrypt`, `aes.generateIv`, `aes.validateIv`, `aes.validateKey`, `aes.generateKey`) are **deprecated**. They have been moved to the `aes.cbc` namespace; `aes.gcm` is now also available. Having a dedicated namespace per mode (`aes.cbc.*`, `aes.gcm.*`) keeps the API unambiguous.

The key difference between the deprecated `aes.*` methods and `aes.cbc.*` is that the old methods **implicitly MD5-hashed** the supplied key, so any string length would work. **`aes.cbc` does not hash the key** — you must supply an exactly 32-character string. Use `await sfet.utils.randomstring.generate(32)` (or `sfet.utils.randomstring.generateSync(32)`) to generate a valid key, or pass your own 32-character string.

The AES secret must be a 32-character string. `aes.cbc` enforces this directly; pass the key as-is (no hashing is applied).

(See [What is the difference between a key, an IV, and a nonce?](https://crypto.stackexchange.com/questions/3965/what-is-the-main-difference-between-a-key-an-iv-and-a-nonce))

**AES-CBC IV**: a 16-character string required by `aes.cbc`. If omitted, a default of `'0000000000000000'` is used. Reusing an IV with the same key leaks information about common plaintext prefixes but is not immediately catastrophic.

**AES-GCM nonce**: a 12-character string required by `aes.gcm`. Unlike CBC's IV, **the nonce is mandatory — no default is provided**. Reusing a GCM nonce with the same key completely destroys both confidentiality and the authentication tag, and can allow an attacker to recover the keystream. Always generate a fresh nonce with `aes.gcm.generateNonce()` for every encryption call and transmit it alongside the ciphertext.

Signing messages and verifying signatures with `simple-free-encryption-tool` are performed using the SHA-256 hashing algorithm.

### Synchronous APIs: `randomstring`, `md5`, `sha256`

- `randomstring.generate`, `md5.hash(message)` and `sha256.hash(message)` are async and return a Promise.
- `randomstring.generateSync()`, `md5.hashSync(message)`, and `sha256.hashSync(message)` are synchronous and return the result directly. These are available in both browser and Node.js environments, but be aware that synchronous hashing can block the main thread in a browser, so use with caution.

All hash methods require a defined, non-null message argument.

## Installation

```bash
npm install simple-free-encryption-tool
```

## Testing and Building

```bash
npm test
npm run build
```

After running the tests, the coverage report will be available at [coverage/index.html](./coverage/index.html).

The coverage badge will be updated automatically.

## Client

```html
<script src="js/windowSfet.js"></script>

<script language="javascript">
        // Call this code when the page is done loading.
        $(async function () {
            alert('random 32 character string generated: ' + await sfet.utils.randomstring.generate(32));
            alert('"secret md5 message" hashed: ' + await sfet.md5.hash('secret md5 message'));
            alert('"secret sha256 message" hashed: ' + await sfet.sha256.hash('secret sha256 message'));

            let keySize = 2048;

            // generateKeys() runs key generation asynchronously
            // this can be called with a callback:
            sfet.rsa.generateKeys(keySize, (error, asyncKeys) => {
                alert(`${asyncKeys.keySize}-bit key pair generated asynchronously in ${asyncKeys.time}ms`);
            });
            // or async/await:
            let asyncKeys = await sfet.rsa.generateKeys(keySize);
            alert(`${asyncKeys.keySize}-bit key pair generated asynchronously in ${asyncKeys.time}ms`);

            // generateKeysSync() runs key generation synchronously
            let keys = sfet.rsa.generateKeysSync(keySize);
            alert('loaded in ' + keys.time);

            let encrypted = await sfet.rsa.encrypt(keys.public, "secret rsa message");
            let decrypted = await sfet.rsa.decrypt(keys.private, encrypted);
            alert('rsa decrypted ' + decrypted);

            // signing an rsa message
            let signature = sfet.rsa.sign(keys.private, "secret rsa message");
            alert('rsa signature ' + signature);
            // verifying an rsa signature
            alert('rsa signature valid: ' + sfet.rsa.verify(keys.public, "secret rsa message", signature))

            // aes.cbc requires an exactly 32-character key
            let aesCbcKey = await sfet.utils.randomstring.generate(32);

            // using default iv of '0000000000000000'
            encrypted = await sfet.aes.cbc.encrypt(aesCbcKey, 'secret aes (cbc) message');
            decrypted = await sfet.aes.cbc.decrypt(aesCbcKey, encrypted);
            alert('aes cbc decrypted ' + decrypted);

            // using generated iv
            let iv = sfet.aes.cbc.generateIv();
            encrypted = await sfet.aes.cbc.encrypt(aesCbcKey, 'secret aes (cbc) message', iv);
            decrypted = await sfet.aes.cbc.decrypt(aesCbcKey, encrypted, iv);
            alert('aes cbc decrypted ' + decrypted);

            // aes.gcm: authenticated encryption — nonce is mandatory and must be
            // unique per (key, message) pair. Never reuse a nonce with the same key.
            let aesGcmKey = await sfet.utils.randomstring.generate(32);
            let nonce = sfet.aes.gcm.generateNonce(); // generate a fresh nonce every time
            encrypted = await sfet.aes.gcm.encrypt(aesGcmKey, 'secret aes (gcm) message', nonce);
            decrypted = await sfet.aes.gcm.decrypt(aesGcmKey, encrypted, nonce);
            alert('aes gcm decrypted ' + decrypted);
        });
    </script>
</head>
```

## Server

```javascript
const sfet = require('simple-free-encryption-tool');

(async () => {
    console.log('random 32 character string generated: ' + await sfet.utils.randomstring.generate(32));
    console.log('"secret md5 message" hashed: ' + await sfet.md5.hash('secret md5 message'));
    console.log('"secret sha256 message" hashed: ' + await sfet.sha256.hash('secret sha256 message'));

    const keySize = 2048;

    // generateKeys() runs key generation asynchronously
    // this can be called with a callback:
    sfet.rsa.generateKeys(keySize, (error, asyncKeys) => {
        console.log(`${asyncKeys.keySize}-bit key pair generated asynchronously in ${asyncKeys.time}ms`);
    });
    // or async/await:
    const asyncKeys = await sfet.rsa.generateKeys(keySize);
    console.log(`${asyncKeys.keySize}-bit key pair generated asynchronously in ${asyncKeys.time}ms`);

    // generateKeysSync() runs key generation synchronously
    const keys = sfet.rsa.generateKeysSync(keySize);
    console.log(`${keys.keySize}-bit key pair generated synchronously in ${keys.time}ms`);

    let encrypted = await sfet.rsa.encrypt(keys.public, "secret rsa message");
    let decrypted = await sfet.rsa.decrypt(keys.private, encrypted);
    console.log('rsa decrypted ' + decrypted);

    // signing an rsa message
    const signature = sfet.rsa.sign(keys.private, "secret rsa message");
    console.log('rsa signature ' + signature);
    // verifying an rsa signature
    console.log('rsa signature valid: ' + sfet.rsa.verify(keys.public, "secret rsa message", signature))

    // aes.cbc requires an exactly 32-character key
    const aesKey = await sfet.utils.randomstring.generate(32);

    // using default iv of '0000000000000000'
    encrypted = await sfet.aes.cbc.encrypt(aesKey, 'secret aes message');
    decrypted = await sfet.aes.cbc.decrypt(aesKey, encrypted);
    console.log('aes cbc decrypted ' + decrypted);

    // using generated iv
    const iv = sfet.aes.cbc.generateIv();
    encrypted = await sfet.aes.cbc.encrypt(aesKey, 'secret aes message', iv);
    decrypted = await sfet.aes.cbc.decrypt(aesKey, encrypted, iv);
    console.log('aes cbc decrypted ' + decrypted);

    // aes.gcm: authenticated encryption — nonce is mandatory and must be
    // unique per (key, message) pair. Never reuse a nonce with the same key.
    const gcmKey = await sfet.utils.randomstring.generate(32);
    const nonce = sfet.aes.gcm.generateNonce(); // generate a fresh nonce every time
    encrypted = await sfet.aes.gcm.encrypt(gcmKey, 'secret aes message', nonce);
    decrypted = await sfet.aes.gcm.decrypt(gcmKey, encrypted, nonce);
    console.log('aes gcm decrypted ' + decrypted);
})();
```

## Utils API: `utils.randomstring`

The `utils.randomstring` object provides a simple utility for generating random alphanumeric strings. **This is an internal implementation** (not the npm `randomstring` package) and uses `globalThis.crypto.getRandomValues()` to ensure browser and Node.js compatibility.

**Methods:**

- `utils.randomstring.generate(options)` (async)
- `utils.randomstring.generateSync(options)` (sync)

- **`options`** (number or object, optional):
  - If a number: generates a string of that length (e.g., `generate(32)` creates a 32-character string).
  - If an object: `{ length: number, charset: string }` to customize the character set.
  - If omitted: defaults to `length: 32` with charset `'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'`.

**Example:**

```javascript
async function examples() {
    // Generate a 32-character random string
    let key = await sfet.utils.randomstring.generate(32);

    // Generate a 16-character string using defaults
    let value = await sfet.utils.randomstring.generate(16);

    // Generate with custom charset
    let hex = await sfet.utils.randomstring.generate({ length: 16, charset: '0123456789abcdef' });
}

// Generate a 32-character random string synchronously
let keySync = sfet.utils.randomstring.generateSync(32);
```
