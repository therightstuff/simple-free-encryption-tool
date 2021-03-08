"use strict";
// module and stand-alone application that generates a PEM formatted RSA key pair

const NodeRSA = require('node-rsa');

const isStandAlone = (process.argv[1] && process.argv[1].indexOf('keyGenerator.js') !== -1);

const INVALID_CALL_WITHOUT_KEYSIZE = 'generateKeys called without keySize argument';

function generateKeys(keySize) {
    if (!keySize) {
        throw new Error(INVALID_CALL_WITHOUT_KEYSIZE);
    }
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