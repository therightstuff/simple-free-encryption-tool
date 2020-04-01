crypto = require('crypto')

console.log(crypto.randomBytes(16).toString('hex').slice(0, 16));