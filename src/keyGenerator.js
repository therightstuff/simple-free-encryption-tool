"use strict";
// module and stand-alone application that generates a PEM formatted RSA key pair

const NodeRSA = require('node-rsa');

const DEFAULT_KEY_SIZE = 2048;

const isStandAlone = (process.argv[1] && process.argv[1].indexOf('keyGenerator.js') !== -1);

function generateKeys(keySize) {
    keySize = keySize || DEFAULT_KEY_SIZE;
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
    // write string directly to stdout without console.log formatting
    process.stdout.write(JSON.stringify(generateKeys()));
} else {
    module.exports = generateKeys;
}