"use strict";
// module and stand-alone application that generates a PEM formatted RSA key pair

// NOTE: at present there is no way to browserify the crypto module, otherwise we
//       could use the crypto module's generateKeyPair methods (see
//       https://medium.com/@yuvrajkakkar1/crypto-nodejs-encryption-issue-rsa-padding-add-pkcs1-type-1-data-too-large-for-key-size-e5e8a52ce8fc)
const NodeRSA = require('node-rsa');

const isStandAlone = (process.argv[1] && process.argv[1].indexOf('keyGenerator.js') !== -1);

function generateKeys(keySize) {
    keySize = Number(keySize);
    let dt = new Date();
    let time = -(dt.getTime());
    let key = new NodeRSA({ b: keySize });
    dt = new Date();
    // time taken to generate keys
    time += (dt.getTime());

    return {
        'keySize': keySize,
        'time': time,
        'private': key.exportKey('pkcs1-private-pem'),
        'public': key.exportKey('pkcs8-public-pem')
    };
}

if (isStandAlone){
    let keySize = process.argv[2];
    // write string directly to stdout without console.log formatting
    process.stdout.write(JSON.stringify(generateKeys(keySize)));
} else {
    module.exports = generateKeys;
}
