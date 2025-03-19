"use strict";

/*
	The node.js modules to be ported to the client must be added
	to the window.cryptoport object.

    "npm run build" must be run after updating this module

    Once bundle has been included in html page with following directive
        <script src="windowSfet.js"></script>
    javascript calls can be made to sfet.* eg
        let encrypted = sfet.aes.encrypt('secret', 'text to be encrypted');
*/

// add required constants to crypto
const crypto = require('crypto');
crypto.constants = {
    RSA_PKCS1_OAEP_PADDING: 4
};

// update the browser's sfet object
window.sfet = {
    aes: require('./security.aes'),
    crypto: crypto,
    md5: require('./security.md5'),
    rsa: require('./security.rsa'),
    sha256: require('./security.sha256'),
    utils: require('./utils')
};
