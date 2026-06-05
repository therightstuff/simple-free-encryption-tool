const md5 = require('md5');

const hash = function(message) {
    if (message === undefined || message === null) {
        throw new TypeError('Illegal argument undefined');
    }
    return md5(String(message));
}

module.exports = {
    hash: async function (message) {
        return hash(message);
    },
    hashSync: hash
};
