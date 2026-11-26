# simple-free-encryption-tool

![](https://img.shields.io/badge/Coverage-100%25-83A603.svg?color=black&prefix=$coverage$)
[![Known Vulnerabilities](https://snyk.io/test/github/therightstuff/simple-free-encryption-tool/badge.svg)](https://snyk.io/test/github/therightstuff/simple-free-encryption-tool)

Easily encrypt and decrypt text in Node.js or a browser. Your server can encrypt a message and your browser can read it with the same secret key. Encryption happens wherever your code runs.

**Try it without writing code.** Open the demo, enter a short message, and try encrypting it and reading it back. [GitHub HTML preview](https://htmlpreview.github.io/?https://github.com/therightstuff/simple-free-encryption-tool/blob/master/dist/index.html)

**Upgrading an existing app?** [Migration guide for users of 4.0.5](docs/usage.md#upgrading-from-405)

## Cryptography 101

**Encrypt a message with AES.** Suppose your server wants to send a private note to a browser. AES uses the same secret key to turn the readable note (*plaintext*) into encrypted data (*ciphertext*) and back again. This is called *symmetric encryption*. Anyone who gets that key can read the note and create another one.

**Detect changes with GCM.** In AES-256-GCM, “256” is the key size in bits, and “GCM” is the way AES is used. A *nonce* means “number used once.” Using a fresh nonce for each encryption under the same key lets you encrypt the same text twice with different results. Reusing one can expose messages and allow forgeries. Each call to `aes.seal` generates the nonce and includes it with the ciphertext and an *authentication tag*. When the browser calls `aes.open`, it checks the tag before returning the note. A changed message or a wrong key makes the check fail. Save or send the whole sealed string and protect the key separately. The package also supports CBC for older data. CBC alone cannot detect tampering.

**Share a secret using RSA.** What if the server and browser don't already share a key? RSA uses a pair of keys. The recipient can share the public key and keep the private key secret. A common design is to encrypt a short, randomly generated shared secret with the recipient’s verified public key. The recipient decrypts it with their private key, and both parties can then use AES for the actual messages. RSA has a small input limit, which is why the shared secret is the part encrypted with RSA. The examples below assume one application already holds the AES key.

**Sign a message to identify its sender.** A sender signs the original text with their private signing key. A recipient who trusts the corresponding public key can verify the signature and detect edits to the text. The text can remain public. Signing and encryption use different operations and padding schemes, so use `rsa.sign` and `rsa.verify` when you need a signature.

## Try it in Node.js

Run this in your application folder:

```sh
npm install simple-free-encryption-tool
```

Save this example as `example.cjs` and run `node example.cjs`. It prints `Meet at noon`.

```js
const { aes } = require('simple-free-encryption-tool');

async function main() {
    const key = await aes.generateKey();
    const encrypted = await aes.seal(key, 'Meet at noon');
    const message = await aes.open(key, encrypted);
    console.log(message); // Meet at noon
}

main().catch(console.error);
```

**Reading it tomorrow?** This example forgets the key when the program exits. To read a saved message, keep the sealed string and load the same secret key. [How to keep a key across restarts](docs/keys-and-messages.md#will-this-still-work-after-a-restart)

## Use it in a browser

Copy [windowSfet.js](dist/js/windowSfet.js) into a folder named `js` beside `index.html`. Put this example in `index.html` and serve it on localhost or HTTPS. The page encrypts a note, then displays the encrypted string and the recovered text.

```html
<!doctype html>
<title>Encrypt a note</title>
<pre id="result"></pre>
<script src="./js/windowSfet.js"></script>
<script type="module">
  const { aes } = window.sfet;
  const key = await aes.generateKey();
  const encrypted = await aes.seal(key, 'Meet at noon');
  const message = await aes.open(key, encrypted);

  document.getElementById('result').textContent =
    `Encrypted: ${encrypted}\nDecrypted: ${message}`;
</script>
```

## What else can I do?

- **Send a short secret to one recipient.** Encrypt it with their public key. They use their private key to read it. [RSA encryption](docs/usage.md#send-a-short-secret)
- **Sign a message.** A recipient who trusts your public key can check that you signed the message and that it arrived unchanged. [Signing example](docs/usage.md#sign-a-message)
- **Compare two copies of some text.** Calculate a checksum for each and compare the results. [Checksum guide](docs/usage.md#calculate-a-checksum)

## Where to go next

- [Supply your own IV and use classic AES-GCM or AES-CBC](docs/usage.md#classic-aes-methods)
- [Extract the IV, ciphertext and tag from a sealed message](docs/keys-and-messages.md#what-does-the-sealed-string-contain)
- [Read data encrypted by older versions](docs/usage.md#read-existing-encrypted-data)
- [Report a security issue privately](SECURITY.md) at **security@industrialcuriosity.com**

[Support the project](https://www.industrialcuriosity.com/p/donate.html)
