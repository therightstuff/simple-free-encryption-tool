"use strict";

/*
	The node.js modules to be ported to the client must be added
	to the window.cryptoport object.

    "npm run build" must be run after updating this module

    Once bundle has been included in html page with following directive
        <script src="windowSfet.js"></script>
    javascript calls can be made to sfet.* eg
        let encrypted = await sfet.aes.cbc.encrypt('my 32 char key!!!!!!!!!!!!!!!!!', 'text to be encrypted', iv);
*/

// All crypto operations use globalThis.crypto.subtle (Web Crypto API),
// available natively in Node.js 20+ and all modern browsers.
// No polyfill or shim required.

// update the browser's sfet object
window.sfet = {
    aes: require('./security.aes'),
    md5: require('./security.md5'),
    rsa: require('./security.rsa'),
    sha256: require('./security.sha256'),
    utils: require('./utils')
};
