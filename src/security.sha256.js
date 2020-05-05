const crypto = require('crypto');

let sha256 = {
	hash: function (message) {
		return crypto.createHash('sha256').update(message).digest("hex");
	}
};

module.exports = sha256;