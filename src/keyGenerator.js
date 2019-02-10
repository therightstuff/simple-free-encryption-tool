"use strict";
// module and stand-alone application that generates a PEM formatted RSA key pair

var NodeRSA = require('node-rsa');

var constants = {
    DEFAULT_KEY_SIZE: 2048
};

const isStandAlone = (process.argv[1] && process.argv[1].indexOf('keyGenerator.js') !== -1);

function generateKeys(keySize) {
    keySize = keySize || constants.DEFAULT_KEY_SIZE;
    var dt = new Date();
    var time = -(dt.getTime());
    var key = new NodeRSA({ b: keySize });
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