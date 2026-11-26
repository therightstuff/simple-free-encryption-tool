# Keeping keys and reading saved messages

Use the [Node.js and browser examples](../README.md#try-it-in-nodejs) to encrypt your first message.

## What do I save?

Save the whole string returned by `aes.seal(key, text)`. You can put it in a database or send it to someone who already has the key. Encrypting the same text twice normally gives two different strings. Both will open with the same key.

Keep the key private and store it separately from the encrypted data. Give it only to people or applications that should be able to read **and create** messages.

## Will this still work after a restart?

Only if you can load the original key again. Calling `generateKey()` creates a different one each time.

- **In a browser**, save the generated key object in IndexedDB. IndexedDB can store it directly. Turning it into JSON loses the key. Clearing the site's data can delete the only copy. Scripts running on your site with access to the key can use it.
- **On a server**, keep a recoverable key in your application's secret store. If your store takes bytes, choose the export option below when creating the key. Load the existing key when the server restarts.

Before relying on either approach, seal a test message, restart the application, load the saved key, and check that the message opens.

## How do I back up or share a key?

By default, Web Crypto lets your application use the key while preventing export of its secret bytes. If you need those bytes, opt in when you first generate the key. These examples use `sfet` and run inside an async function.

```js
const key = await sfet.aes.generateKey({ extractable: true });
const keyBytes = await crypto.subtle.exportKey('raw', key);
// Save keyBytes in your secret store before relying on this key.
```

When you retrieve those bytes from the store, turn them back into a usable key:

```js
const key = await crypto.subtle.importKey(
    'raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']
);
const text = await sfet.aes.open(key, encrypted);
```

Anyone who copies the bytes has the key. Keep them out of logs, source code and messages containing the encrypted text. Base64 is an encoding anyone can reverse. For another recipient, use a separate, protected way to deliver the key.

## Why won't my message open?

1. Check that you loaded the key that encrypted this message. A new key generated at startup is a common cause.
2. Pass the complete string returned by `seal`, including its `sfet1.` prefix. Changing or truncating it can cause `open` to reject it.
3. If older code used `aes.cbc.encrypt` or `aes.gcm.encrypt`, use the matching method to read it. [Older encryption formats](usage.md#read-existing-encrypted-data)

Treat a rejected `open` call as a failed read. A wrong key and damaged data can produce the same error.

## What does the sealed string contain?

A GCM *nonce* means “number used once.” It gives each encryption with the same key a fresh starting value. Other libraries call it the *initialization vector* (IV). You can read it, the encrypted bytes, and the authentication tag without the key:

```js
const iv = aes.extractIv(sealed);                 // 12 bytes
const ciphertext = aes.extractCiphertext(sealed); // Encrypted text only
const tag = aes.extractTag(sealed);               // 16 bytes
```

Each helper returns a `Uint8Array` synchronously and throws for an invalid envelope format. Extraction only separates the fields. To check authenticity, decrypt with the key and verify the tag. For example, in Node.js with the same AES key as a `CryptoKey`:

```js
const { createDecipheriv } = require('node:crypto');
const decipher = createDecipheriv('aes-256-gcm', key, iv);
decipher.setAAD(Buffer.from('sfet1', 'utf8'));
decipher.setAuthTag(tag);
const text = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
```

For a library that takes ciphertext and tag together (including Web Crypto), append the tag to the ciphertext before decrypting. Version 1 starts with `sfet1.`. Decode the rest as standard Base64. The first 12 bytes are a random nonce (a public value generated for each encryption). The remaining bytes are the AES-256-GCM encrypted UTF-8 text followed by its 16-byte authentication tag. The UTF-8 bytes of `sfet1` are authenticated as additional data. Only the key needs to stay secret.

The tag lets the reader detect changes. The encrypted message still reveals the text's byte length, and someone can resend a valid message. If receiving it twice would cause a problem, include a unique message ID in the encrypted text and track which IDs the application has accepted.

For high-volume use, rotate to a new key before 2³² encryptions with the same key, counting all devices and processes together. The package leaves counting and rotation to the application. [NIST SP 800-38D §8.3](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf)
