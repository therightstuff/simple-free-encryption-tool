# Using the library

## Get the library

**Node.js.** Install with `npm install simple-free-encryption-tool` and load it with `const sfet = require('simple-free-encryption-tool')`. See the [npm quick start](../README.md#try-it-in-nodejs) for a complete example.

**Browser.** Copy [windowSfet.js](../dist/js/windowSfet.js) from this repository into your site's JavaScript folder. Load it before your own script on an HTTPS page or localhost:

```html
<script src="./js/windowSfet.js"></script>
```

Your script can now use `window.sfet.aes`. The calls in the [README example](../README.md#try-it-in-nodejs) work the same way once you set `const { aes } = window.sfet`.

## Upgrading from 4.0.5

Existing CBC and GCM records can stay as they are. Keep their original keys and any stored IVs or nonces. Update the parts of your app that write or read them in this order:

1. **Check storage and validation.** If you store generated CBC IVs, allow both the old 16-character strings and the new 32-character hex strings. For generated GCM nonces, allow both 12 and 24 characters. Check database columns, API validation and client forms. Preserve old values exactly, including leading zeros.
2. **Update readers first.** Deploy the new library anywhere ciphertext is decrypted, including browser clients. Test a saved record from the old version. If the original CBC writer omitted the IV, continue calling `aes.cbc.decrypt(key, encrypted)` for those records. Each such read logs a security warning.
3. **Update writers.** Replace each two-argument CBC encryption call with the example below. Generate a fresh IV per message and save the IV and ciphertext together. An integration that already supplies and stores valid IVs can keep its existing format.
4. **Check a new record end to end.** Write it, reload it from storage, and decrypt it in each supported client. Old readers cannot consume the wider generated values or sealed messages. If you roll back writers after new records exist, keep the upgraded readers available.

For a CBC writer that previously omitted the IV, use this inside an async function with your existing key:

```js
const iv = aes.cbc.generateIv();
const record = { iv, encrypted: await aes.cbc.encrypt(key, 'Meet at noon', iv) };
// Save both fields. After loading the record:
const message = await aes.cbc.decrypt(key, record.encrypted, record.iv);
```

Adopting `aes.seal` is optional. If you choose it for new records, keep the sealed string and its key, and route those records to `aes.open`. Continue using the [matching classic decrypt method](#read-existing-encrypted-data) for earlier records.

## Classic AES methods

Use these methods when you need to store the IV separately or match another system’s format. Both take a 32-character ASCII secret key and encode the key and message as UTF-8. A GCM *nonce* (“number used once”) is the public starting value, also called the initialization vector (IV). Generate a fresh one for every encryption with a given key. Reuse can expose the messages and let someone forge a valid tag.

Inside an async function:

```js
const { aes, utils } = require('simple-free-encryption-tool');
const key = await utils.randomstring.generate(32);

const nonce = aes.gcm.generateNonce();
const encrypted = await aes.gcm.encrypt(key, 'Meet at noon', nonce);
const message = await aes.gcm.decrypt(key, encrypted, nonce);

// For an integration that requires CBC:
const iv = aes.cbc.generateIv();
const encryptedCbc = await aes.cbc.encrypt(key, 'Meet at noon', iv);
const messageCbc = await aes.cbc.decrypt(key, encryptedCbc, iv);
```

**Matching another library.** Supply the same key bytes on both sides. A key string containing hex digits is still read as UTF-8 text. Store the IV or nonce with the encrypted string and keep the secret key separately.

| Setting | Classic AES-GCM | Classic AES-CBC |
| --- | --- | --- |
| Generated IV | Decode 24 hex digits to 12 bytes | Decode 32 hex digits to 16 bytes |
| Encrypted string | Standard Base64 of ciphertext followed by a 16-byte tag | Standard Base64 of PKCS#7-padded, encrypted data |
| Other settings | Empty additional authenticated data (AAD), 128-bit tag, no padding | 16-byte blocks, PKCS#7 padding, no authentication tag |

Older 12-character GCM nonces and 16-character CBC IVs use their original UTF-8 bytes, even if they look like hex. For new CBC encryptions always generate a fresh, unpredictable IV. For the versioned output of `seal`, use its [format and extraction helpers](keys-and-messages.md#what-does-the-sealed-string-contain). Its additional authenticated data differs from classic GCM.

## Read existing encrypted data

Find the method the application used to encrypt the data. Keep the original key and any value saved alongside the encrypted text.

| Written with | Read with |
| --- | --- |
| `aes.seal` | `await aes.open(key, encrypted)` |
| `aes.gcm.encrypt` | `await aes.gcm.decrypt(key, encrypted, nonce)` |
| `aes.cbc.encrypt` with an IV | `await aes.cbc.decrypt(key, encrypted, iv)` |
| Older CBC with the IV omitted | `await aes.cbc.decrypt(key, encrypted)` |

The last call logs a warning because old versions reused a fixed starting value. CBC also cannot verify whether someone changed the encrypted data. If your old application used the removed top-level AES methods, check its key handling first. Those methods hashed the supplied key with MD5. The current CBC API uses the supplied key directly.

Historical C# interoperability examples are in [v2.0.14](https://github.com/therightstuff/simple-free-encryption-tool/tree/v2.0.14).

## Sign a message

A signature lets someone check that a message came from the holder of a particular private key and has stayed intact. The message remains readable. Give the recipient your public key through a channel they trust. Keep the private key secret.

```js
const keys = await sfet.rsa.generateKeys(2048);
const signature = sfet.rsa.sign(keys.private, 'Approved');
const valid = sfet.rsa.verify(keys.public, 'Approved', signature); // true
```

## Send a short secret

If an integration requires RSA encryption of a short secret, use `await sfet.rsa.encrypt(publicKey, secret)` and `await sfet.rsa.decrypt(privateKey, encrypted)`. RSA has a small message-size limit. Use sealed messages for ordinary text. RSA key generation also accepts an optional callback with `(error, keys)`.

## Calculate a checksum

Use `await sfet.sha256.hash(text)` to get a fingerprint you can compare with a trusted expected value. **MD5 is for matching legacy checksums only.** A checksum by itself cannot prove who sent a message. Both modules also provide `hashSync(text)` for synchronous callers.

## Generate a random string

`await sfet.utils.randomstring.generate(16)` returns 16 random letters and digits. With no argument it returns 32. To choose the alphabet, pass an object such as `{ length: 16, charset: '0123456789abcdef' }`. Use `generateSync` for a synchronous result. For sealed messages, use `aes.generateKey()`.

## Test and build

From the checkout, run `npm ci` to install dependencies, then `npm run build` to run the tests and rebuild the browser bundle. Use `npm test` for tests alone. The suite checks AES-GCM against [published OpenSSL examples](https://github.com/openssl/openssl/blob/master/test/recipes/30-test_evp_data/evpciph_aes_common.txt). Open `coverage/index.html` locally for the coverage report.

After building, run `npm run test:browser` to check that Node.js and a real browser can open each other's messages. Set `CHROME_BIN` to your Chromium-based browser executable if it is outside the default Linux location.
