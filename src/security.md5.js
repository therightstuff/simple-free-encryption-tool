const crypto = require('crypto');

let md5 = {
	hash: function (message) {
		return crypto.createHash('md5').update(message).digest("hex");
	}
};

module.exports = md5;