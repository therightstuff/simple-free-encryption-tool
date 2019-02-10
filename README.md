# simple-free-encryption-tool
Simple Free RSA / AES Encryption and Decryption

Simple Free Encryption Tool (sfet) uses RSA and AES versions that are strong and allow encryption between client-side Javascript, Node.js and C#.

Open and free for all to see, can be run stand-alone for extra security.

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

// rsa.generateKeys() runs key generation in a separate child process
rsa.generateKeys(defaultKeySize, (error, generatedKeyPair) => {
    ...
});

var keys = sfet.rsa.generateKeysSync();
console.log(keys.keySize + '-bit key pair generated in ' + keys.time + 'ms');

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