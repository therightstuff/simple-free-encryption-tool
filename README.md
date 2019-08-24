# simple-free-encryption-tool
Simple Free RSA / AES Encryption and Decryption

Simple Free Encryption Tool (sfet) uses RSA and AES versions that are strong and allow encryption between client-side Javascript, Node.js and C#.

Open and free for all to see, can be run stand-alone on a local machine for an extra sense of security; all functionality runs entirely locally once the page has been loaded.
Latest client version be loaded directly from the GitHub repo [here](http://htmlpreview.github.io/?https://github.com/therightstuff/simple-free-encryption-tool/blob/master/dist/index.html).

## Encryption 101
RSA encryption operates on a very limited string length, it is generally used to asymmetrically encrypt a shared secret that in turn is used for symmetric encryption. The standard use-case is to generate a random shared secret and transmit it encrypted with the destination's public RSA key. Once the destination has decrypted the shared secret with its private RSA key both sides will be able to use that secret to encrypt and decrypt communication with AES.

## Installation
```
npm install simple-free-encryption-tool
```

## Testing and Building
```
npm test
npm run build
```

## Client
```
<script src="js/windowSfet.js"></script>

<script language="javascript">
        // Call this code when the page is done loading.
        $(function () {
            alert('"secret md5 message" hashed: ' + sfet.md5.hash('secret md5 message'));

            // asynchronous not available in browser, can be implemented using HTML5 Worker class
            var keys = sfet.rsa.generateKeysSync();
            alert('loaded in ' + keys.time);

            var encrypted = sfet.rsa.encrypt(keys.public, "secret rsa message");
            var decrypted = sfet.rsa.decrypt(keys.private, encrypted);
            alert('rsa decrypted ' + decrypted);
            
            encrypted = sfet.aes.encrypt('secret', 'secret aes message')
            decrypted = sfet.aes.decrypt('secret', encrypted);
            alert('aes decrypted ' + decrypted);
        });
    </script>
    </script>
</head>
```

## Server
```
const sfet = require('simple-free-encryption-tool');

// (key size defaults to 2048 if null)
var keySize = 2048;

// generateKeys() runs key generation in a separate child process
sfet.rsa.generateKeys(keySize, (error, keys) => {
    console.log(keys.keySize + '-bit key pair generated asynchronously in ' + keys.time + 'ms');
});

var keys = sfet.rsa.generateKeysSync(keySize);
console.log(keys.keySize + '-bit key pair generated synchronously in ' + keys.time + 'ms');

var encrypted = sfet.rsa.encrypt(keys.public, "secret rsa message");
var decrypted = sfet.rsa.decrypt(keys.private, encrypted);
console.log('rsa decrypted ' + decrypted);

encrypted = sfet.aes.encrypt('secret', 'secret aes message')
decrypted = sfet.aes.decrypt('secret', encrypted);
console.log('aes decrypted ' + decrypted);
```
## C# compatibility

C# counterparts available here:
* RSA key importer / exporter: https://gist.github.com/therightstuff/aa65356e95f8d0aae888e9f61aa29414
* RSA encrypt / decrypt: https://gist.github.com/therightstuff/4db89368887dba2fe8935b2fb329f5aa
* AES encrypt / decrypt: https://gist.github.com/therightstuff/30e5cbd9b1e0de1b8865c8fb6e2971e4