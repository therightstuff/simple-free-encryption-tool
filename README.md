# simple-free-encryption-tool

![Coverage Badge 100%](https://img.shields.io/badge/Coverage-100%25-83A603.svg?color=black&prefix=![](https://img.shields.io/badge/Coverage-100%25-83A603.svg?color=black&prefix=$coverage$))
[![Known Vulnerabilities](https://snyk.io/test/github/therightstuff/simple-free-encryption-tool/badge.svg)](https://snyk.io/test/github/therightstuff/simple-free-encryption-tool)

## Simple Free RSA / AES Encryption and Decryption

Simple Free Encryption Tool (sfet) uses RSA and AES versions that are strong and allow encryption between client-side Javascript, Node.js and C#.

Open and free for all to see, can be run stand-alone on a local machine for an extra sense of security; all functionality runs entirely locally once the page has been loaded.

Latest client version be loaded directly from the GitHub repo [here](http://htmlpreview.github.io/?https://github.com/therightstuff/simple-free-encryption-tool/blob/master/dist/index.html).
As that service hasn't been working lately (due to CORS issues, apparently), I've also made it available on [industrialcuriosity.com](https://industrialcuriosity.com/sfet).

If you've found this tool useful, [please consider making a donation](https://www.industrialcuriosity.com/p/donate.html)!

## Encryption 101

RSA encryption operates on a very limited string length, it is generally used to asymmetrically encrypt a shared secret that in turn is used for symmetric encryption. The standard use-case is to generate a random shared secret and transmit it encrypted with the destination's public RSA key. Once the destination has decrypted the shared secret with its private RSA key both sides will be able to use that secret to encrypt and decrypt communication with AES.

Signing a message to prove authorship (and that it hasn't been tampered with) is performed on the plaintext message, and the resulting signature can only be verified with the public key matching the private key it was signed with. The padding for signing and verifying signatures is not the same as for encrypting and decrypting messages.

## Important Notes

The AES secret must be a 32 character string. In order to ensure a valid string, the provided secret is always hashed using the MD5 algorithm to produce a string of the correct length.

The IV, or Initialization Vector, is a 16 character hexadecimal string that's required by the AES algorithm ([read this](https://crypto.stackexchange.com/questions/3965/what-is-the-main-difference-between-a-key-an-iv-and-a-nonce) for a detailed explanation). It's not really necessary when encryption secrets aren't being reused, but as it's enforced by the underlying crypto package it's recommended to include it. If you do choose to leave it out, a default IV of '0000000000000000' will be used.

Signing messages and verifying signatures with simple-free-encryption-tool are performed using the SHA-256 hashing algorithm.

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

Pull Requests will run `package.json`'s `test` and `build` scripts in [CodeSandbox CI](https://codesandbox.io/docs/ci).

## Client

```html
<script src="js/windowSfet.js"></script>

<script language="javascript">
        // Call this code when the page is done loading.
        $(function () {
            alert('random 32 character string generated: ' + sfet.utils.randomstring.generate(32));
            alert('"secret md5 message" hashed: ' + sfet.md5.hash('secret md5 message'));
            alert('"secret sha256 message" hashed: ' + sfet.sha256.hash('secret sha256 message'));

            // asynchronous not available in browser, can be implemented using HTML5 Worker class
            let keySize = 2048;
            let keys = sfet.rsa.generateKeysSync(keySize);
            alert('loaded in ' + keys.time);

            let encrypted = sfet.rsa.encrypt(keys.public, "secret rsa message");
            let decrypted = sfet.rsa.decrypt(keys.private, encrypted);
            alert('rsa decrypted ' + decrypted);

            // signing an rsa message
            let signature = sfet.rsa.sign(keys.private, "secret rsa message");
            alert('rsa signature ' + signature);
            // verifying an rsa signature
            alert('rsa signature valid: ' + sfet.rsa.verify(keys.public, "secret rsa message", signature))

            // using default iv of '0000000000000000'
            encrypted = sfet.aes.encrypt('secret', 'secret aes message')
            decrypted = sfet.aes.decrypt('secret', encrypted);
            alert('aes decrypted ' + decrypted);

            // using generated iv
            let iv = sfet.aes.generateIv();
            encrypted = sfet.aes.encrypt('secret', 'secret aes message', iv)
            decrypted = sfet.aes.decrypt('secret', encrypted, iv);
            alert('aes decrypted ' + decrypted);
        });
    </script>
    </script>
</head>
```

## Server

```javascript
const sfet = require('simple-free-encryption-tool');

console.log('random 32 character string generated: ' + sfet.utils.randomstring.generate(32));
console.log('"secret md5 message" hashed: ' + sfet.md5.hash('secret md5 message'));
console.log('"secret sha256 message" hashed: ' + sfet.sha256.hash('secret sha256 message'));

let keySize = 2048;

// generateKeys() runs key generation in a separate child process
sfet.rsa.generateKeys(keySize, (error, keys) => {
    console.log(keys.keySize + '-bit key pair generated asynchronously in ' + keys.time + 'ms');
});

let keys = sfet.rsa.generateKeysSync(keySize);
console.log(keys.keySize + '-bit key pair generated synchronously in ' + keys.time + 'ms');

let encrypted = sfet.rsa.encrypt(keys.public, "secret rsa message");
let decrypted = sfet.rsa.decrypt(keys.private, encrypted);
console.log('rsa decrypted ' + decrypted);

// signing an rsa message
let signature = sfet.rsa.sign(keys.private, "secret rsa message");
console.log('rsa signature ' + signature);
// verifying an rsa signature
console.log('rsa signature valid: ' + sfet.rsa.verify(keys.public, "secret rsa message", signature))

// using default iv of '0000000000000000'
encrypted = sfet.aes.encrypt('secret', 'secret aes message')
decrypted = sfet.aes.decrypt('secret', encrypted);
console.log('aes decrypted ' + decrypted);

// using generated iv
iv = sfet.aes.generateIv();
encrypted = sfet.aes.encrypt('secret', 'secret aes message', iv)
decrypted = sfet.aes.decrypt('secret', encrypted, iv);
console.log('aes decrypted ' + decrypted);
```

## C# compatibility

C# counterparts available in the `/examples/csharp` folder as well as on gist:

* [RSA key importer / exporter](https://gist.github.com/therightstuff/aa65356e95f8d0aae888e9f61aa29414)
* [RSA encrypt / decrypt / sign / verify](https://gist.github.com/therightstuff/4db89368887dba2fe8935b2fb329f5aa)
* [AES encrypt / decrypt](https://gist.github.com/therightstuff/30e5cbd9b1e0de1b8865c8fb6e2971e4)
