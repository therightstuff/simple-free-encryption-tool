"use strict";
(() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __esm = (fn, res) => function __init() {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  };
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // src/security.aes.js
  var require_security_aes = __commonJS({
    "src/security.aes.js"(exports, module) {
      var INVALID_IV_ERROR = "Invalid iv, 16-character string required";
      var INVALID_KEY_ERROR = "Invalid key, 32-character string required";
      var INVALID_GCM_NONCE_ERROR = "Invalid nonce, 12-character string required";
      var NULL_IV = "0000000000000000";
      var cbc = {
        INVALID_IV_ERROR,
        INVALID_KEY_ERROR,
        NULL_IV,
        algorithm: "AES-CBC",
        encrypt: async function(key, message, iv) {
          iv = iv || cbc.NULL_IV;
          cbc.validateKey(key);
          cbc.validateIv(iv);
          if (message === null || message === void 0) {
            throw new TypeError('The "data" argument must be a string');
          }
          const keyBytes = new TextEncoder().encode(key);
          const ivBytes = new TextEncoder().encode(iv);
          const cryptoKey = await globalThis.crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "AES-CBC" },
            false,
            ["encrypt"]
          );
          const msgBytes = new TextEncoder().encode(message);
          const encrypted = await globalThis.crypto.subtle.encrypt(
            { name: "AES-CBC", iv: ivBytes },
            cryptoKey,
            msgBytes
          );
          return btoa(String.fromCodePoint(...new Uint8Array(encrypted)));
        },
        decrypt: async function(key, message, iv) {
          iv = iv || cbc.NULL_IV;
          cbc.validateKey(key);
          cbc.validateIv(iv);
          const keyBytes = new TextEncoder().encode(key);
          const ivBytes = new TextEncoder().encode(iv);
          const cryptoKey = await globalThis.crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "AES-CBC" },
            false,
            ["decrypt"]
          );
          let msgBytes;
          try {
            msgBytes = Uint8Array.from(atob(message), (c) => c.codePointAt(0));
          } catch (err) {
            throw new Error(err.message || "AES-CBC decryption failed (invalid ciphertext)");
          }
          const decrypted = await globalThis.crypto.subtle.decrypt(
            { name: "AES-CBC", iv: ivBytes },
            cryptoKey,
            msgBytes
          );
          return new TextDecoder().decode(decrypted);
        },
        generateIv: function() {
          const bytes = new Uint8Array(8);
          globalThis.crypto.getRandomValues(bytes);
          return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
        },
        validateIv: function(iv) {
          if (iv?.length != 16) {
            throw new Error(cbc.INVALID_IV_ERROR);
          }
        },
        validateKey: function(key) {
          if (key?.length != 32) {
            throw new Error(cbc.INVALID_KEY_ERROR);
          }
        }
      };
      var gcm = {
        INVALID_KEY_ERROR,
        INVALID_NONCE_ERROR: INVALID_GCM_NONCE_ERROR,
        algorithm: "AES-GCM",
        encrypt: async function(key, message, nonce) {
          gcm.validateKey(key);
          gcm.validateNonce(nonce);
          if (message === null || message === void 0) {
            throw new TypeError('The "data" argument must be a string');
          }
          const keyBytes = new TextEncoder().encode(key);
          const nonceBytes = new TextEncoder().encode(nonce);
          const cryptoKey = await globalThis.crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
          );
          const msgBytes = new TextEncoder().encode(message);
          const encrypted = await globalThis.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
            cryptoKey,
            msgBytes
          );
          return btoa(String.fromCodePoint(...new Uint8Array(encrypted)));
        },
        decrypt: async function(key, message, nonce) {
          gcm.validateKey(key);
          gcm.validateNonce(nonce);
          const keyBytes = new TextEncoder().encode(key);
          const nonceBytes = new TextEncoder().encode(nonce);
          const cryptoKey = await globalThis.crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          );
          let msgBytes;
          try {
            msgBytes = Uint8Array.from(atob(message), (c) => c.codePointAt(0));
          } catch (err) {
            throw new Error(err.message || "AES-GCM decryption failed (invalid ciphertext)");
          }
          try {
            const decrypted = await globalThis.crypto.subtle.decrypt(
              { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
              cryptoKey,
              msgBytes
            );
            return new TextDecoder().decode(decrypted);
          } catch (err) {
            throw new Error(err.message || "AES-GCM decryption failed (authentication error)");
          }
        },
        generateNonce: function() {
          const bytes = new Uint8Array(6);
          globalThis.crypto.getRandomValues(bytes);
          return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 12);
        },
        validateNonce: function(nonce) {
          if (nonce?.length != 12) {
            throw new Error(gcm.INVALID_NONCE_ERROR);
          }
        },
        validateKey: function(key) {
          if (key?.length != 32) {
            throw new Error(gcm.INVALID_KEY_ERROR);
          }
        }
      };
      module.exports = { cbc, gcm };
    }
  });

  // node_modules/crypt/crypt.js
  var require_crypt = __commonJS({
    "node_modules/crypt/crypt.js"(exports, module) {
      (function() {
        var base64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", crypt = {
          // Bit-wise rotation left
          rotl: function(n, b) {
            return n << b | n >>> 32 - b;
          },
          // Bit-wise rotation right
          rotr: function(n, b) {
            return n << 32 - b | n >>> b;
          },
          // Swap big-endian to little-endian and vice versa
          endian: function(n) {
            if (n.constructor == Number) {
              return crypt.rotl(n, 8) & 16711935 | crypt.rotl(n, 24) & 4278255360;
            }
            for (var i = 0; i < n.length; i++)
              n[i] = crypt.endian(n[i]);
            return n;
          },
          // Generate an array of any length of random bytes
          randomBytes: function(n) {
            for (var bytes = []; n > 0; n--)
              bytes.push(Math.floor(Math.random() * 256));
            return bytes;
          },
          // Convert a byte array to big-endian 32-bit words
          bytesToWords: function(bytes) {
            for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
              words[b >>> 5] |= bytes[i] << 24 - b % 32;
            return words;
          },
          // Convert big-endian 32-bit words to a byte array
          wordsToBytes: function(words) {
            for (var bytes = [], b = 0; b < words.length * 32; b += 8)
              bytes.push(words[b >>> 5] >>> 24 - b % 32 & 255);
            return bytes;
          },
          // Convert a byte array to a hex string
          bytesToHex: function(bytes) {
            for (var hex = [], i = 0; i < bytes.length; i++) {
              hex.push((bytes[i] >>> 4).toString(16));
              hex.push((bytes[i] & 15).toString(16));
            }
            return hex.join("");
          },
          // Convert a hex string to a byte array
          hexToBytes: function(hex) {
            for (var bytes = [], c = 0; c < hex.length; c += 2)
              bytes.push(parseInt(hex.substr(c, 2), 16));
            return bytes;
          },
          // Convert a byte array to a base-64 string
          bytesToBase64: function(bytes) {
            for (var base64 = [], i = 0; i < bytes.length; i += 3) {
              var triplet = bytes[i] << 16 | bytes[i + 1] << 8 | bytes[i + 2];
              for (var j = 0; j < 4; j++)
                if (i * 8 + j * 6 <= bytes.length * 8)
                  base64.push(base64map.charAt(triplet >>> 6 * (3 - j) & 63));
                else
                  base64.push("=");
            }
            return base64.join("");
          },
          // Convert a base-64 string to a byte array
          base64ToBytes: function(base64) {
            base64 = base64.replace(/[^A-Z0-9+\/]/ig, "");
            for (var bytes = [], i = 0, imod4 = 0; i < base64.length; imod4 = ++i % 4) {
              if (imod4 == 0) continue;
              bytes.push((base64map.indexOf(base64.charAt(i - 1)) & Math.pow(2, -2 * imod4 + 8) - 1) << imod4 * 2 | base64map.indexOf(base64.charAt(i)) >>> 6 - imod4 * 2);
            }
            return bytes;
          }
        };
        module.exports = crypt;
      })();
    }
  });

  // node_modules/charenc/charenc.js
  var require_charenc = __commonJS({
    "node_modules/charenc/charenc.js"(exports, module) {
      var charenc = {
        // UTF-8 encoding
        utf8: {
          // Convert a string to a byte array
          stringToBytes: function(str) {
            return charenc.bin.stringToBytes(unescape(encodeURIComponent(str)));
          },
          // Convert a byte array to a string
          bytesToString: function(bytes) {
            return decodeURIComponent(escape(charenc.bin.bytesToString(bytes)));
          }
        },
        // Binary encoding
        bin: {
          // Convert a string to a byte array
          stringToBytes: function(str) {
            for (var bytes = [], i = 0; i < str.length; i++)
              bytes.push(str.charCodeAt(i) & 255);
            return bytes;
          },
          // Convert a byte array to a string
          bytesToString: function(bytes) {
            for (var str = [], i = 0; i < bytes.length; i++)
              str.push(String.fromCharCode(bytes[i]));
            return str.join("");
          }
        }
      };
      module.exports = charenc;
    }
  });

  // node_modules/is-buffer/index.js
  var require_is_buffer = __commonJS({
    "node_modules/is-buffer/index.js"(exports, module) {
      module.exports = function(obj) {
        return obj != null && (isBuffer(obj) || isSlowBuffer(obj) || !!obj._isBuffer);
      };
      function isBuffer(obj) {
        return !!obj.constructor && typeof obj.constructor.isBuffer === "function" && obj.constructor.isBuffer(obj);
      }
      function isSlowBuffer(obj) {
        return typeof obj.readFloatLE === "function" && typeof obj.slice === "function" && isBuffer(obj.slice(0, 0));
      }
    }
  });

  // node_modules/md5/md5.js
  var require_md5 = __commonJS({
    "node_modules/md5/md5.js"(exports, module) {
      (function() {
        var crypt = require_crypt(), utf8 = require_charenc().utf8, isBuffer = require_is_buffer(), bin = require_charenc().bin, md52 = function(message, options) {
          if (message.constructor == String)
            if (options && options.encoding === "binary")
              message = bin.stringToBytes(message);
            else
              message = utf8.stringToBytes(message);
          else if (isBuffer(message))
            message = Array.prototype.slice.call(message, 0);
          else if (!Array.isArray(message) && message.constructor !== Uint8Array)
            message = message.toString();
          var m = crypt.bytesToWords(message), l = message.length * 8, a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
          for (var i = 0; i < m.length; i++) {
            m[i] = (m[i] << 8 | m[i] >>> 24) & 16711935 | (m[i] << 24 | m[i] >>> 8) & 4278255360;
          }
          m[l >>> 5] |= 128 << l % 32;
          m[(l + 64 >>> 9 << 4) + 14] = l;
          var FF = md52._ff, GG = md52._gg, HH = md52._hh, II = md52._ii;
          for (var i = 0; i < m.length; i += 16) {
            var aa = a, bb = b, cc = c, dd = d;
            a = FF(a, b, c, d, m[i + 0], 7, -680876936);
            d = FF(d, a, b, c, m[i + 1], 12, -389564586);
            c = FF(c, d, a, b, m[i + 2], 17, 606105819);
            b = FF(b, c, d, a, m[i + 3], 22, -1044525330);
            a = FF(a, b, c, d, m[i + 4], 7, -176418897);
            d = FF(d, a, b, c, m[i + 5], 12, 1200080426);
            c = FF(c, d, a, b, m[i + 6], 17, -1473231341);
            b = FF(b, c, d, a, m[i + 7], 22, -45705983);
            a = FF(a, b, c, d, m[i + 8], 7, 1770035416);
            d = FF(d, a, b, c, m[i + 9], 12, -1958414417);
            c = FF(c, d, a, b, m[i + 10], 17, -42063);
            b = FF(b, c, d, a, m[i + 11], 22, -1990404162);
            a = FF(a, b, c, d, m[i + 12], 7, 1804603682);
            d = FF(d, a, b, c, m[i + 13], 12, -40341101);
            c = FF(c, d, a, b, m[i + 14], 17, -1502002290);
            b = FF(b, c, d, a, m[i + 15], 22, 1236535329);
            a = GG(a, b, c, d, m[i + 1], 5, -165796510);
            d = GG(d, a, b, c, m[i + 6], 9, -1069501632);
            c = GG(c, d, a, b, m[i + 11], 14, 643717713);
            b = GG(b, c, d, a, m[i + 0], 20, -373897302);
            a = GG(a, b, c, d, m[i + 5], 5, -701558691);
            d = GG(d, a, b, c, m[i + 10], 9, 38016083);
            c = GG(c, d, a, b, m[i + 15], 14, -660478335);
            b = GG(b, c, d, a, m[i + 4], 20, -405537848);
            a = GG(a, b, c, d, m[i + 9], 5, 568446438);
            d = GG(d, a, b, c, m[i + 14], 9, -1019803690);
            c = GG(c, d, a, b, m[i + 3], 14, -187363961);
            b = GG(b, c, d, a, m[i + 8], 20, 1163531501);
            a = GG(a, b, c, d, m[i + 13], 5, -1444681467);
            d = GG(d, a, b, c, m[i + 2], 9, -51403784);
            c = GG(c, d, a, b, m[i + 7], 14, 1735328473);
            b = GG(b, c, d, a, m[i + 12], 20, -1926607734);
            a = HH(a, b, c, d, m[i + 5], 4, -378558);
            d = HH(d, a, b, c, m[i + 8], 11, -2022574463);
            c = HH(c, d, a, b, m[i + 11], 16, 1839030562);
            b = HH(b, c, d, a, m[i + 14], 23, -35309556);
            a = HH(a, b, c, d, m[i + 1], 4, -1530992060);
            d = HH(d, a, b, c, m[i + 4], 11, 1272893353);
            c = HH(c, d, a, b, m[i + 7], 16, -155497632);
            b = HH(b, c, d, a, m[i + 10], 23, -1094730640);
            a = HH(a, b, c, d, m[i + 13], 4, 681279174);
            d = HH(d, a, b, c, m[i + 0], 11, -358537222);
            c = HH(c, d, a, b, m[i + 3], 16, -722521979);
            b = HH(b, c, d, a, m[i + 6], 23, 76029189);
            a = HH(a, b, c, d, m[i + 9], 4, -640364487);
            d = HH(d, a, b, c, m[i + 12], 11, -421815835);
            c = HH(c, d, a, b, m[i + 15], 16, 530742520);
            b = HH(b, c, d, a, m[i + 2], 23, -995338651);
            a = II(a, b, c, d, m[i + 0], 6, -198630844);
            d = II(d, a, b, c, m[i + 7], 10, 1126891415);
            c = II(c, d, a, b, m[i + 14], 15, -1416354905);
            b = II(b, c, d, a, m[i + 5], 21, -57434055);
            a = II(a, b, c, d, m[i + 12], 6, 1700485571);
            d = II(d, a, b, c, m[i + 3], 10, -1894986606);
            c = II(c, d, a, b, m[i + 10], 15, -1051523);
            b = II(b, c, d, a, m[i + 1], 21, -2054922799);
            a = II(a, b, c, d, m[i + 8], 6, 1873313359);
            d = II(d, a, b, c, m[i + 15], 10, -30611744);
            c = II(c, d, a, b, m[i + 6], 15, -1560198380);
            b = II(b, c, d, a, m[i + 13], 21, 1309151649);
            a = II(a, b, c, d, m[i + 4], 6, -145523070);
            d = II(d, a, b, c, m[i + 11], 10, -1120210379);
            c = II(c, d, a, b, m[i + 2], 15, 718787259);
            b = II(b, c, d, a, m[i + 9], 21, -343485551);
            a = a + aa >>> 0;
            b = b + bb >>> 0;
            c = c + cc >>> 0;
            d = d + dd >>> 0;
          }
          return crypt.endian([a, b, c, d]);
        };
        md52._ff = function(a, b, c, d, x, s, t) {
          var n = a + (b & c | ~b & d) + (x >>> 0) + t;
          return (n << s | n >>> 32 - s) + b;
        };
        md52._gg = function(a, b, c, d, x, s, t) {
          var n = a + (b & d | c & ~d) + (x >>> 0) + t;
          return (n << s | n >>> 32 - s) + b;
        };
        md52._hh = function(a, b, c, d, x, s, t) {
          var n = a + (b ^ c ^ d) + (x >>> 0) + t;
          return (n << s | n >>> 32 - s) + b;
        };
        md52._ii = function(a, b, c, d, x, s, t) {
          var n = a + (c ^ (b | ~d)) + (x >>> 0) + t;
          return (n << s | n >>> 32 - s) + b;
        };
        md52._blocksize = 16;
        md52._digestsize = 16;
        module.exports = function(message, options) {
          if (message === void 0 || message === null)
            throw new Error("Illegal argument " + message);
          var digestbytes = crypt.wordsToBytes(md52(message, options));
          return options && options.asBytes ? digestbytes : options && options.asString ? bin.bytesToString(digestbytes) : crypt.bytesToHex(digestbytes);
        };
      })();
    }
  });

  // src/security.md5.js
  var require_security_md5 = __commonJS({
    "src/security.md5.js"(exports, module) {
      var md52 = require_md5();
      var hash = function(message) {
        if (message === void 0 || message === null) {
          throw new TypeError("Illegal argument undefined");
        }
        return md52(String(message));
      };
      module.exports = {
        hash: async function(message) {
          return hash(message);
        },
        hashSync: hash
      };
    }
  });

  // node_modules/@noble/hashes/utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
  }
  function abytes(value, length, title = "") {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== void 0;
    if (!bytes || needsLen && len !== length) {
      const prefix = title && `"${title}" `;
      const ofLen = needsLen ? ` of length ${length}` : "";
      const got = bytes ? `length=${len}` : `type=${typeof value}`;
      const message = prefix + "expected Uint8Array" + ofLen + ", got " + got;
      if (!bytes)
        throw new TypeError(message);
      throw new RangeError(message);
    }
    return value;
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished)
      throw new Error("Hash#digest() has already been called");
  }
  function aoutput(out, instance) {
    abytes(out, void 0, "digestInto() output");
    const min = instance.outputLen;
    if (out.length < min) {
      throw new RangeError('"digestInto() output" expected to be of length >=' + min);
    }
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr(word, shift) {
    return word << 32 - shift | word >>> shift;
  }
  function rotl(word, shift) {
    return word << shift | word >>> 32 - shift >>> 0;
  }
  function createHasher(hashCons, info = {}) {
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(void 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.canXOF = tmp.canXOF;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
  }
  var oidNist;
  var init_utils = __esm({
    "node_modules/@noble/hashes/utils.js"() {
      oidNist = (suffix) => ({
        // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
        // Larger suffix values would need base-128 OID encoding and a different length byte.
        oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
      });
    }
  });

  // node_modules/@noble/hashes/_md.js
  function Chi(a, b, c) {
    return a & b ^ ~a & c;
  }
  function Maj(a, b, c) {
    return a & b ^ a & c ^ b & c;
  }
  var HashMD, SHA256_IV, SHA224_IV, SHA384_IV, SHA512_IV;
  var init_md = __esm({
    "node_modules/@noble/hashes/_md.js"() {
      init_utils();
      HashMD = class {
        blockLen;
        outputLen;
        canXOF = false;
        padOffset;
        isLE;
        // For partial updates less than block size
        buffer;
        view;
        finished = false;
        length = 0;
        pos = 0;
        destroyed = false;
        constructor(blockLen, outputLen, padOffset, isLE) {
          this.blockLen = blockLen;
          this.outputLen = outputLen;
          this.padOffset = padOffset;
          this.isLE = isLE;
          this.buffer = new Uint8Array(blockLen);
          this.view = createView(this.buffer);
        }
        update(data) {
          aexists(this);
          abytes(data);
          const { view, buffer, blockLen } = this;
          const len = data.length;
          for (let pos = 0; pos < len; ) {
            const take = Math.min(blockLen - this.pos, len - pos);
            if (take === blockLen) {
              const dataView = createView(data);
              for (; blockLen <= len - pos; pos += blockLen)
                this.process(dataView, pos);
              continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
              this.process(view, 0);
              this.pos = 0;
            }
          }
          this.length += data.length;
          this.roundClean();
          return this;
        }
        digestInto(out) {
          aexists(this);
          aoutput(out, this);
          this.finished = true;
          const { buffer, view, blockLen, isLE } = this;
          let { pos } = this;
          buffer[pos++] = 128;
          clean(this.buffer.subarray(pos));
          if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
          }
          for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
          view.setBigUint64(blockLen - 8, BigInt(this.length * 8), isLE);
          this.process(view, 0);
          const oview = createView(out);
          const len = this.outputLen;
          if (len % 4)
            throw new Error("_sha2: outputLen must be aligned to 32bit");
          const outLen = len / 4;
          const state = this.get();
          if (outLen > state.length)
            throw new Error("_sha2: outputLen bigger than state");
          for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
        }
        digest() {
          const { buffer, outputLen } = this;
          this.digestInto(buffer);
          const res = buffer.slice(0, outputLen);
          this.destroy();
          return res;
        }
        _cloneInto(to) {
          to ||= new this.constructor();
          to.set(...this.get());
          const { blockLen, buffer, length, finished, destroyed, pos } = this;
          to.destroyed = destroyed;
          to.finished = finished;
          to.length = length;
          to.pos = pos;
          if (length % blockLen)
            to.buffer.set(buffer);
          return to;
        }
        clone() {
          return this._cloneInto();
        }
      };
      SHA256_IV = /* @__PURE__ */ Uint32Array.from([
        1779033703,
        3144134277,
        1013904242,
        2773480762,
        1359893119,
        2600822924,
        528734635,
        1541459225
      ]);
      SHA224_IV = /* @__PURE__ */ Uint32Array.from([
        3238371032,
        914150663,
        812702999,
        4144912697,
        4290775857,
        1750603025,
        1694076839,
        3204075428
      ]);
      SHA384_IV = /* @__PURE__ */ Uint32Array.from([
        3418070365,
        3238371032,
        1654270250,
        914150663,
        2438529370,
        812702999,
        355462360,
        4144912697,
        1731405415,
        4290775857,
        2394180231,
        1750603025,
        3675008525,
        1694076839,
        1203062813,
        3204075428
      ]);
      SHA512_IV = /* @__PURE__ */ Uint32Array.from([
        1779033703,
        4089235720,
        3144134277,
        2227873595,
        1013904242,
        4271175723,
        2773480762,
        1595750129,
        1359893119,
        2917565137,
        2600822924,
        725511199,
        528734635,
        4215389547,
        1541459225,
        327033209
      ]);
    }
  });

  // node_modules/@noble/hashes/legacy.js
  function ripemd_f(group, x, y, z) {
    if (group === 0)
      return x ^ y ^ z;
    if (group === 1)
      return x & y | ~x & z;
    if (group === 2)
      return (x | ~y) ^ z;
    if (group === 3)
      return x & z | y & ~z;
    return x ^ (y | ~z);
  }
  var SHA1_IV, SHA1_W, _SHA1, sha1, p32, K, MD5_IV, MD5_W, _MD5, md5, Rho160, Id160, Pi160, idxLR, idxL, idxR, shifts160, shiftsL160, shiftsR160, Kl160, Kr160, BUF_160, _RIPEMD160, ripemd160;
  var init_legacy = __esm({
    "node_modules/@noble/hashes/legacy.js"() {
      init_md();
      init_utils();
      SHA1_IV = /* @__PURE__ */ Uint32Array.from([
        1732584193,
        4023233417,
        2562383102,
        271733878,
        3285377520
      ]);
      SHA1_W = /* @__PURE__ */ new Uint32Array(80);
      _SHA1 = class extends HashMD {
        A = SHA1_IV[0] | 0;
        B = SHA1_IV[1] | 0;
        C = SHA1_IV[2] | 0;
        D = SHA1_IV[3] | 0;
        E = SHA1_IV[4] | 0;
        constructor() {
          super(64, 20, 8, false);
        }
        get() {
          const { A, B, C, D, E } = this;
          return [A, B, C, D, E];
        }
        set(A, B, C, D, E) {
          this.A = A | 0;
          this.B = B | 0;
          this.C = C | 0;
          this.D = D | 0;
          this.E = E | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4)
            SHA1_W[i] = view.getUint32(offset, false);
          for (let i = 16; i < 80; i++)
            SHA1_W[i] = rotl(SHA1_W[i - 3] ^ SHA1_W[i - 8] ^ SHA1_W[i - 14] ^ SHA1_W[i - 16], 1);
          let { A, B, C, D, E } = this;
          for (let i = 0; i < 80; i++) {
            let F, K2;
            if (i < 20) {
              F = Chi(B, C, D);
              K2 = 1518500249;
            } else if (i < 40) {
              F = B ^ C ^ D;
              K2 = 1859775393;
            } else if (i < 60) {
              F = Maj(B, C, D);
              K2 = 2400959708;
            } else {
              F = B ^ C ^ D;
              K2 = 3395469782;
            }
            const T = rotl(A, 5) + F + E + K2 + SHA1_W[i] | 0;
            E = D;
            D = C;
            C = rotl(B, 30);
            B = A;
            A = T;
          }
          A = A + this.A | 0;
          B = B + this.B | 0;
          C = C + this.C | 0;
          D = D + this.D | 0;
          E = E + this.E | 0;
          this.set(A, B, C, D, E);
        }
        roundClean() {
          clean(SHA1_W);
        }
        destroy() {
          this.destroyed = true;
          this.set(0, 0, 0, 0, 0);
          clean(this.buffer);
        }
      };
      sha1 = /* @__PURE__ */ createHasher(() => new _SHA1());
      p32 = /* @__PURE__ */ Math.pow(2, 32);
      K = /* @__PURE__ */ Array.from({ length: 64 }, (_, i) => Math.floor(p32 * Math.abs(Math.sin(i + 1))));
      MD5_IV = /* @__PURE__ */ SHA1_IV.slice(0, 4);
      MD5_W = /* @__PURE__ */ new Uint32Array(16);
      _MD5 = class extends HashMD {
        A = MD5_IV[0] | 0;
        B = MD5_IV[1] | 0;
        C = MD5_IV[2] | 0;
        D = MD5_IV[3] | 0;
        constructor() {
          super(64, 16, 8, true);
        }
        get() {
          const { A, B, C, D } = this;
          return [A, B, C, D];
        }
        set(A, B, C, D) {
          this.A = A | 0;
          this.B = B | 0;
          this.C = C | 0;
          this.D = D | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4)
            MD5_W[i] = view.getUint32(offset, true);
          let { A, B, C, D } = this;
          for (let i = 0; i < 64; i++) {
            let F, g, s;
            if (i < 16) {
              F = Chi(B, C, D);
              g = i;
              s = [7, 12, 17, 22];
            } else if (i < 32) {
              F = Chi(D, B, C);
              g = (5 * i + 1) % 16;
              s = [5, 9, 14, 20];
            } else if (i < 48) {
              F = B ^ C ^ D;
              g = (3 * i + 5) % 16;
              s = [4, 11, 16, 23];
            } else {
              F = C ^ (B | ~D);
              g = 7 * i % 16;
              s = [6, 10, 15, 21];
            }
            F = F + A + K[i] + MD5_W[g];
            A = D;
            D = C;
            C = B;
            B = B + rotl(F, s[i % 4]);
          }
          A = A + this.A | 0;
          B = B + this.B | 0;
          C = C + this.C | 0;
          D = D + this.D | 0;
          this.set(A, B, C, D);
        }
        roundClean() {
          clean(MD5_W);
        }
        destroy() {
          this.destroyed = true;
          this.set(0, 0, 0, 0);
          clean(this.buffer);
        }
      };
      md5 = /* @__PURE__ */ createHasher(() => new _MD5());
      Rho160 = /* @__PURE__ */ Uint8Array.from([
        7,
        4,
        13,
        1,
        10,
        6,
        15,
        3,
        12,
        0,
        9,
        5,
        2,
        14,
        11,
        8
      ]);
      Id160 = /* @__PURE__ */ (() => Uint8Array.from(new Array(16).fill(0).map((_, i) => i)))();
      Pi160 = /* @__PURE__ */ (() => Id160.map((i) => (9 * i + 5) % 16))();
      idxLR = /* @__PURE__ */ (() => {
        const L = [Id160];
        const R = [Pi160];
        const res = [L, R];
        for (let i = 0; i < 4; i++)
          for (let j of res)
            j.push(j[i].map((k) => Rho160[k]));
        return res;
      })();
      idxL = /* @__PURE__ */ (() => idxLR[0])();
      idxR = /* @__PURE__ */ (() => idxLR[1])();
      shifts160 = /* @__PURE__ */ [
        [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
        [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
        [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
        [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
        [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
      ].map((i) => Uint8Array.from(i));
      shiftsL160 = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts160[i][j]));
      shiftsR160 = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts160[i][j]));
      Kl160 = /* @__PURE__ */ Uint32Array.from([
        0,
        1518500249,
        1859775393,
        2400959708,
        2840853838
      ]);
      Kr160 = /* @__PURE__ */ Uint32Array.from([
        1352829926,
        1548603684,
        1836072691,
        2053994217,
        0
      ]);
      BUF_160 = /* @__PURE__ */ new Uint32Array(16);
      _RIPEMD160 = class extends HashMD {
        h0 = 1732584193 | 0;
        h1 = 4023233417 | 0;
        h2 = 2562383102 | 0;
        h3 = 271733878 | 0;
        h4 = 3285377520 | 0;
        constructor() {
          super(64, 20, 8, true);
        }
        get() {
          const { h0, h1, h2, h3, h4 } = this;
          return [h0, h1, h2, h3, h4];
        }
        set(h0, h1, h2, h3, h4) {
          this.h0 = h0 | 0;
          this.h1 = h1 | 0;
          this.h2 = h2 | 0;
          this.h3 = h3 | 0;
          this.h4 = h4 | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4)
            BUF_160[i] = view.getUint32(offset, true);
          let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
          for (let group = 0; group < 5; group++) {
            const rGroup = 4 - group;
            const hbl = Kl160[group], hbr = Kr160[group];
            const rl = idxL[group], rr = idxR[group];
            const sl = shiftsL160[group], sr = shiftsR160[group];
            for (let i = 0; i < 16; i++) {
              const tl = rotl(al + ripemd_f(group, bl, cl, dl) + BUF_160[rl[i]] + hbl, sl[i]) + el | 0;
              al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl;
            }
            for (let i = 0; i < 16; i++) {
              const tr = rotl(ar + ripemd_f(rGroup, br, cr, dr) + BUF_160[rr[i]] + hbr, sr[i]) + er | 0;
              ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr;
            }
          }
          this.set(this.h1 + cl + dr | 0, this.h2 + dl + er | 0, this.h3 + el + ar | 0, this.h4 + al + br | 0, this.h0 + bl + cr | 0);
        }
        roundClean() {
          clean(BUF_160);
        }
        destroy() {
          this.destroyed = true;
          clean(this.buffer);
          this.set(0, 0, 0, 0, 0);
        }
      };
      ripemd160 = /* @__PURE__ */ createHasher(() => new _RIPEMD160());
    }
  });

  // node_modules/@noble/hashes/_u64.js
  function fromBig(n, le = false) {
    if (le)
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
  }
  function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  }
  function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
  }
  var U32_MASK64, _32n, shrSH, shrSL, rotrSH, rotrSL, rotrBH, rotrBL, add3L, add3H, add4L, add4H, add5L, add5H;
  var init_u64 = __esm({
    "node_modules/@noble/hashes/_u64.js"() {
      U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
      _32n = /* @__PURE__ */ BigInt(32);
      shrSH = (h, _l, s) => h >>> s;
      shrSL = (h, l, s) => h << 32 - s | l >>> s;
      rotrSH = (h, l, s) => h >>> s | l << 32 - s;
      rotrSL = (h, l, s) => h << 32 - s | l >>> s;
      rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
      rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
      add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
      add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
      add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
      add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
      add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
      add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
    }
  });

  // node_modules/@noble/hashes/sha2.js
  var SHA256_K, SHA256_W, SHA2_32B, _SHA256, _SHA224, K512, SHA512_Kh, SHA512_Kl, SHA512_W_H, SHA512_W_L, SHA2_64B, _SHA512, _SHA384, sha256, sha224, sha512, sha384;
  var init_sha2 = __esm({
    "node_modules/@noble/hashes/sha2.js"() {
      init_md();
      init_u64();
      init_utils();
      SHA256_K = /* @__PURE__ */ Uint32Array.from([
        1116352408,
        1899447441,
        3049323471,
        3921009573,
        961987163,
        1508970993,
        2453635748,
        2870763221,
        3624381080,
        310598401,
        607225278,
        1426881987,
        1925078388,
        2162078206,
        2614888103,
        3248222580,
        3835390401,
        4022224774,
        264347078,
        604807628,
        770255983,
        1249150122,
        1555081692,
        1996064986,
        2554220882,
        2821834349,
        2952996808,
        3210313671,
        3336571891,
        3584528711,
        113926993,
        338241895,
        666307205,
        773529912,
        1294757372,
        1396182291,
        1695183700,
        1986661051,
        2177026350,
        2456956037,
        2730485921,
        2820302411,
        3259730800,
        3345764771,
        3516065817,
        3600352804,
        4094571909,
        275423344,
        430227734,
        506948616,
        659060556,
        883997877,
        958139571,
        1322822218,
        1537002063,
        1747873779,
        1955562222,
        2024104815,
        2227730452,
        2361852424,
        2428436474,
        2756734187,
        3204031479,
        3329325298
      ]);
      SHA256_W = /* @__PURE__ */ new Uint32Array(64);
      SHA2_32B = class extends HashMD {
        constructor(outputLen) {
          super(64, outputLen, 8, false);
        }
        get() {
          const { A, B, C, D, E, F, G, H } = this;
          return [A, B, C, D, E, F, G, H];
        }
        // prettier-ignore
        set(A, B, C, D, E, F, G, H) {
          this.A = A | 0;
          this.B = B | 0;
          this.C = C | 0;
          this.D = D | 0;
          this.E = E | 0;
          this.F = F | 0;
          this.G = G | 0;
          this.H = H | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
          for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
            SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
          }
          let { A, B, C, D, E, F, G, H } = this;
          for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = sigma0 + Maj(A, B, C) | 0;
            H = G;
            G = F;
            F = E;
            E = D + T1 | 0;
            D = C;
            C = B;
            B = A;
            A = T1 + T2 | 0;
          }
          A = A + this.A | 0;
          B = B + this.B | 0;
          C = C + this.C | 0;
          D = D + this.D | 0;
          E = E + this.E | 0;
          F = F + this.F | 0;
          G = G + this.G | 0;
          H = H + this.H | 0;
          this.set(A, B, C, D, E, F, G, H);
        }
        roundClean() {
          clean(SHA256_W);
        }
        destroy() {
          this.destroyed = true;
          this.set(0, 0, 0, 0, 0, 0, 0, 0);
          clean(this.buffer);
        }
      };
      _SHA256 = class extends SHA2_32B {
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        A = SHA256_IV[0] | 0;
        B = SHA256_IV[1] | 0;
        C = SHA256_IV[2] | 0;
        D = SHA256_IV[3] | 0;
        E = SHA256_IV[4] | 0;
        F = SHA256_IV[5] | 0;
        G = SHA256_IV[6] | 0;
        H = SHA256_IV[7] | 0;
        constructor() {
          super(32);
        }
      };
      _SHA224 = class extends SHA2_32B {
        A = SHA224_IV[0] | 0;
        B = SHA224_IV[1] | 0;
        C = SHA224_IV[2] | 0;
        D = SHA224_IV[3] | 0;
        E = SHA224_IV[4] | 0;
        F = SHA224_IV[5] | 0;
        G = SHA224_IV[6] | 0;
        H = SHA224_IV[7] | 0;
        constructor() {
          super(28);
        }
      };
      K512 = /* @__PURE__ */ (() => split([
        "0x428a2f98d728ae22",
        "0x7137449123ef65cd",
        "0xb5c0fbcfec4d3b2f",
        "0xe9b5dba58189dbbc",
        "0x3956c25bf348b538",
        "0x59f111f1b605d019",
        "0x923f82a4af194f9b",
        "0xab1c5ed5da6d8118",
        "0xd807aa98a3030242",
        "0x12835b0145706fbe",
        "0x243185be4ee4b28c",
        "0x550c7dc3d5ffb4e2",
        "0x72be5d74f27b896f",
        "0x80deb1fe3b1696b1",
        "0x9bdc06a725c71235",
        "0xc19bf174cf692694",
        "0xe49b69c19ef14ad2",
        "0xefbe4786384f25e3",
        "0x0fc19dc68b8cd5b5",
        "0x240ca1cc77ac9c65",
        "0x2de92c6f592b0275",
        "0x4a7484aa6ea6e483",
        "0x5cb0a9dcbd41fbd4",
        "0x76f988da831153b5",
        "0x983e5152ee66dfab",
        "0xa831c66d2db43210",
        "0xb00327c898fb213f",
        "0xbf597fc7beef0ee4",
        "0xc6e00bf33da88fc2",
        "0xd5a79147930aa725",
        "0x06ca6351e003826f",
        "0x142929670a0e6e70",
        "0x27b70a8546d22ffc",
        "0x2e1b21385c26c926",
        "0x4d2c6dfc5ac42aed",
        "0x53380d139d95b3df",
        "0x650a73548baf63de",
        "0x766a0abb3c77b2a8",
        "0x81c2c92e47edaee6",
        "0x92722c851482353b",
        "0xa2bfe8a14cf10364",
        "0xa81a664bbc423001",
        "0xc24b8b70d0f89791",
        "0xc76c51a30654be30",
        "0xd192e819d6ef5218",
        "0xd69906245565a910",
        "0xf40e35855771202a",
        "0x106aa07032bbd1b8",
        "0x19a4c116b8d2d0c8",
        "0x1e376c085141ab53",
        "0x2748774cdf8eeb99",
        "0x34b0bcb5e19b48a8",
        "0x391c0cb3c5c95a63",
        "0x4ed8aa4ae3418acb",
        "0x5b9cca4f7763e373",
        "0x682e6ff3d6b2b8a3",
        "0x748f82ee5defb2fc",
        "0x78a5636f43172f60",
        "0x84c87814a1f0ab72",
        "0x8cc702081a6439ec",
        "0x90befffa23631e28",
        "0xa4506cebde82bde9",
        "0xbef9a3f7b2c67915",
        "0xc67178f2e372532b",
        "0xca273eceea26619c",
        "0xd186b8c721c0c207",
        "0xeada7dd6cde0eb1e",
        "0xf57d4f7fee6ed178",
        "0x06f067aa72176fba",
        "0x0a637dc5a2c898a6",
        "0x113f9804bef90dae",
        "0x1b710b35131c471b",
        "0x28db77f523047d84",
        "0x32caab7b40c72493",
        "0x3c9ebe0a15c9bebc",
        "0x431d67c49c100d4c",
        "0x4cc5d4becb3e42b6",
        "0x597f299cfc657e2a",
        "0x5fcb6fab3ad6faec",
        "0x6c44198c4a475817"
      ].map((n) => BigInt(n))))();
      SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
      SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
      SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
      SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
      SHA2_64B = class extends HashMD {
        constructor(outputLen) {
          super(128, outputLen, 16, false);
        }
        // prettier-ignore
        get() {
          const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
          return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
        }
        // prettier-ignore
        set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
          this.Ah = Ah | 0;
          this.Al = Al | 0;
          this.Bh = Bh | 0;
          this.Bl = Bl | 0;
          this.Ch = Ch | 0;
          this.Cl = Cl | 0;
          this.Dh = Dh | 0;
          this.Dl = Dl | 0;
          this.Eh = Eh | 0;
          this.El = El | 0;
          this.Fh = Fh | 0;
          this.Fl = Fl | 0;
          this.Gh = Gh | 0;
          this.Gl = Gl | 0;
          this.Hh = Hh | 0;
          this.Hl = Hl | 0;
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4) {
            SHA512_W_H[i] = view.getUint32(offset);
            SHA512_W_L[i] = view.getUint32(offset += 4);
          }
          for (let i = 16; i < 80; i++) {
            const W15h = SHA512_W_H[i - 15] | 0;
            const W15l = SHA512_W_L[i - 15] | 0;
            const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
            const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
            const W2h = SHA512_W_H[i - 2] | 0;
            const W2l = SHA512_W_L[i - 2] | 0;
            const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
            const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
            const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
            const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
            SHA512_W_H[i] = SUMh | 0;
            SHA512_W_L[i] = SUMl | 0;
          }
          let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
          for (let i = 0; i < 80; i++) {
            const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
            const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
            const CHIh = Eh & Fh ^ ~Eh & Gh;
            const CHIl = El & Fl ^ ~El & Gl;
            const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
            const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
            const T1l = T1ll | 0;
            const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
            const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
            const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
            const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
            Hh = Gh | 0;
            Hl = Gl | 0;
            Gh = Fh | 0;
            Gl = Fl | 0;
            Fh = Eh | 0;
            Fl = El | 0;
            ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
            Dh = Ch | 0;
            Dl = Cl | 0;
            Ch = Bh | 0;
            Cl = Bl | 0;
            Bh = Ah | 0;
            Bl = Al | 0;
            const All = add3L(T1l, sigma0l, MAJl);
            Ah = add3H(All, T1h, sigma0h, MAJh);
            Al = All | 0;
          }
          ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
          ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
          ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
          ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
          ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
          ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
          ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
          ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
          this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
        }
        roundClean() {
          clean(SHA512_W_H, SHA512_W_L);
        }
        destroy() {
          this.destroyed = true;
          clean(this.buffer);
          this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
      };
      _SHA512 = class extends SHA2_64B {
        Ah = SHA512_IV[0] | 0;
        Al = SHA512_IV[1] | 0;
        Bh = SHA512_IV[2] | 0;
        Bl = SHA512_IV[3] | 0;
        Ch = SHA512_IV[4] | 0;
        Cl = SHA512_IV[5] | 0;
        Dh = SHA512_IV[6] | 0;
        Dl = SHA512_IV[7] | 0;
        Eh = SHA512_IV[8] | 0;
        El = SHA512_IV[9] | 0;
        Fh = SHA512_IV[10] | 0;
        Fl = SHA512_IV[11] | 0;
        Gh = SHA512_IV[12] | 0;
        Gl = SHA512_IV[13] | 0;
        Hh = SHA512_IV[14] | 0;
        Hl = SHA512_IV[15] | 0;
        constructor() {
          super(64);
        }
      };
      _SHA384 = class extends SHA2_64B {
        Ah = SHA384_IV[0] | 0;
        Al = SHA384_IV[1] | 0;
        Bh = SHA384_IV[2] | 0;
        Bl = SHA384_IV[3] | 0;
        Ch = SHA384_IV[4] | 0;
        Cl = SHA384_IV[5] | 0;
        Dh = SHA384_IV[6] | 0;
        Dl = SHA384_IV[7] | 0;
        Eh = SHA384_IV[8] | 0;
        El = SHA384_IV[9] | 0;
        Fh = SHA384_IV[10] | 0;
        Fl = SHA384_IV[11] | 0;
        Gh = SHA384_IV[12] | 0;
        Gl = SHA384_IV[13] | 0;
        Hh = SHA384_IV[14] | 0;
        Hl = SHA384_IV[15] | 0;
        constructor() {
          super(48);
        }
      };
      sha256 = /* @__PURE__ */ createHasher(
        () => new _SHA256(),
        /* @__PURE__ */ oidNist(1)
      );
      sha224 = /* @__PURE__ */ createHasher(
        () => new _SHA224(),
        /* @__PURE__ */ oidNist(4)
      );
      sha512 = /* @__PURE__ */ createHasher(
        () => new _SHA512(),
        /* @__PURE__ */ oidNist(3)
      );
      sha384 = /* @__PURE__ */ createHasher(
        () => new _SHA384(),
        /* @__PURE__ */ oidNist(2)
      );
    }
  });

  // node_modules/node-rsa/dist/index.browser.js
  var index_browser_exports = {};
  __export(index_browser_exports, {
    NodeRSA: () => NodeRSA,
    default: () => index_browser_default
  });
  function setBigIntegerBackend(backend) {
    _backend = backend;
  }
  function getBackend() {
    if (!_backend) {
      throw new Error(
        "BigInteger crypto backend not initialized. Did you import from src/index.node.ts or src/index.browser.ts?"
      );
    }
    return _backend;
  }
  function int2char(n) {
    return BI_RM.charAt(n);
  }
  function intAt(s, i) {
    const c = BI_RC[s.charCodeAt(i)];
    return c == null ? -1 : c;
  }
  function nbits(x) {
    let r = 1;
    let t;
    if ((t = x >>> 16) !== 0) {
      x = t;
      r += 16;
    }
    if ((t = x >> 8) !== 0) {
      x = t;
      r += 8;
    }
    if ((t = x >> 4) !== 0) {
      x = t;
      r += 4;
    }
    if ((t = x >> 2) !== 0) {
      x = t;
      r += 2;
    }
    if ((t = x >> 1) !== 0) {
      r += 1;
    }
    return r;
  }
  function lbit(x) {
    if (x === 0) return -1;
    let r = 0;
    if ((x & 65535) === 0) {
      x >>= 16;
      r += 16;
    }
    if ((x & 255) === 0) {
      x >>= 8;
      r += 8;
    }
    if ((x & 15) === 0) {
      x >>= 4;
      r += 4;
    }
    if ((x & 3) === 0) {
      x >>= 2;
      r += 2;
    }
    if ((x & 1) === 0) ++r;
    return r;
  }
  function cbit(x) {
    let r = 0;
    while (x !== 0) {
      x &= x - 1;
      ++r;
    }
    return r;
  }
  function nbi() {
    return new BigInteger(null);
  }
  function nbv(i) {
    const r = nbi();
    r.fromInt(i);
    return r;
  }
  function op_and(x, y) {
    return x & y;
  }
  function op_or(x, y) {
    return x | y;
  }
  function op_xor(x, y) {
    return x ^ y;
  }
  function op_andnot(x, y) {
    return x & ~y;
  }
  function setBigIntegerBackend2(backend) {
    _backend2 = backend;
  }
  function getBackend2() {
    if (!_backend2) {
      throw new Error(
        "BigInteger (native): backend not set. Did you import the package via its main entry?"
      );
    }
    return _backend2;
  }
  function bytesToBigInt(bytes, unsigned) {
    if (bytes.length === 0) return ZERO_BI;
    if (!unsigned && (bytes[0] & 128) !== 0) {
      let inv = ZERO_BI;
      for (let i = 0; i < bytes.length; i++) {
        inv = inv << 8n | BigInt(bytes[i] ^ 255);
      }
      return -(inv + ONE_BI);
    }
    let v = ZERO_BI;
    for (let i = 0; i < bytes.length; i++) {
      v = v << 8n | BigInt(bytes[i]);
    }
    return v;
  }
  function bigIntToBytes(v, length) {
    if (v < ZERO_BI) throw new Error("BigInteger.toBuffer: negative value");
    if (v === ZERO_BI) return new Uint8Array(length ?? 1);
    let hex = v.toString(16);
    if (hex.length & 1) hex = `0${hex}`;
    const raw = new Uint8Array(hex.length / 2);
    for (let i = 0; i < raw.length; i++) {
      raw[i] = Number.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    if (length === void 0) {
      if (raw[0] & 128) {
        const padded = new Uint8Array(raw.length + 1);
        padded.set(raw, 1);
        return padded;
      }
      return raw;
    }
    if (length === raw.length) return raw;
    if (length < raw.length) {
      let cut = 0;
      while (cut < raw.length - length && raw[cut] === 0) cut++;
      if (raw.length - cut === length) return raw.slice(cut);
      return raw.slice(raw.length - length);
    }
    const out = new Uint8Array(length);
    out.set(raw, length - raw.length);
    return out;
  }
  function bitLengthOf(v) {
    if (v === ZERO_BI) return 0;
    const x = v < ZERO_BI ? -v : v;
    return x.toString(2).length;
  }
  function modPowBI(base, exp, mod) {
    if (mod === ONE_BI) return ZERO_BI;
    if (exp < ZERO_BI) {
      return modPowBI(modInverseBI(base, mod), -exp, mod);
    }
    let b = base % mod;
    if (b < ZERO_BI) b += mod;
    let result = ONE_BI;
    let e = exp;
    while (e > ZERO_BI) {
      if (e & ONE_BI) result = result * b % mod;
      e >>= ONE_BI;
      b = b * b % mod;
    }
    return result;
  }
  function modInverseBI(a, m) {
    if (m <= ZERO_BI) throw new Error("BigInteger.modInverse: modulus must be positive");
    let aNorm = a % m;
    if (aNorm < ZERO_BI) aNorm += m;
    let oldR = aNorm;
    let r = m;
    let oldS = ONE_BI;
    let s = ZERO_BI;
    while (r !== ZERO_BI) {
      const q = oldR / r;
      [oldR, r] = [r, oldR - q * r];
      [oldS, s] = [s, oldS - q * s];
    }
    if (oldR !== ONE_BI) return ZERO_BI;
    return oldS < ZERO_BI ? oldS + m : oldS;
  }
  function gcdBI(a, b) {
    let x = a < ZERO_BI ? -a : a;
    let y = b < ZERO_BI ? -b : b;
    while (y !== ZERO_BI) {
      [x, y] = [y, x % y];
    }
    return x;
  }
  function millerRabin(n, rounds) {
    if (n < TWO_BI) return false;
    if (n === TWO_BI || n === 3n) return true;
    if ((n & ONE_BI) === ZERO_BI) return false;
    const nMinus1 = n - ONE_BI;
    let s = 0;
    let d = nMinus1;
    while ((d & ONE_BI) === ZERO_BI) {
      d >>= ONE_BI;
      s++;
    }
    const byteLen = (bitLengthOf(n) + 7 >> 3) + 1;
    const backend = getBackend2();
    const nMinus3 = n - 3n;
    witnessLoop: for (let i = 0; i < rounds; i++) {
      let a;
      for (; ; ) {
        a = bytesToBigInt(backend.randomBytes(byteLen), true) % nMinus3;
        a += TWO_BI;
        if (a >= TWO_BI && a <= nMinus1 - ONE_BI) break;
      }
      let x = modPowBI(a, d, n);
      if (x === ONE_BI || x === nMinus1) continue;
      for (let r = 1; r < s; r++) {
        x = x * x % n;
        if (x === nMinus1) continue witnessLoop;
      }
      return false;
    }
    return true;
  }
  function probablePrime(v, rounds) {
    if (v < TWO_BI) return false;
    for (const p of SMALL_PRIMES_BI) {
      if (v === p) return true;
      if (v % p === ZERO_BI) return false;
    }
    return millerRabin(v, rounds);
  }
  function generateProbablePrime(bits) {
    if (bits < 2) throw new Error("BigInteger: cannot generate prime with < 2 bits");
    const byteLen = bits + 7 >> 3;
    const backend = getBackend2();
    while (true) {
      const x = backend.randomBytes(byteLen);
      const tailBits = bits & 7;
      if (tailBits > 0) x[0] = x[0] & (1 << tailBits) - 1;
      let v = bytesToBigInt(x, true);
      v |= ONE_BI << BigInt(bits - 1);
      v |= ONE_BI;
      for (let step = 0; step < 1 << 15; step += 2) {
        if (bitLengthOf(v) > bits) break;
        if (probablePrime(v, 1)) return v;
        v += TWO_BI;
      }
    }
  }
  function parseFromString(s, radix) {
    if (s.length === 0) return ZERO_BI;
    let str = s;
    let neg = false;
    if (str[0] === "-") {
      neg = true;
      str = str.substring(1);
    }
    if (str.length === 0) return ZERO_BI;
    let v;
    if (radix === 10) {
      v = BigInt(str);
    } else if (radix === 16) {
      v = BigInt(`0x${str}`);
    } else {
      const r = BigInt(radix);
      v = ZERO_BI;
      for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        let d;
        if (code >= 48 && code <= 57) d = code - 48;
        else if (code >= 65 && code <= 90) d = code - 55;
        else if (code >= 97 && code <= 122) d = code - 87;
        else continue;
        if (d < 0 || d >= radix) continue;
        v = v * r + BigInt(d);
      }
    }
    return neg ? -v : v;
  }
  function setBigIntegerImpl(impl) {
    if (impl === "native" && typeof BigInt === "function") {
      BigInteger3 = BigInteger2;
      _currentImpl = "native";
    } else {
      BigInteger3 = BigInteger;
      _currentImpl = "jsbn";
    }
    if (_currentBackend) {
      setBigIntegerBackend(_currentBackend);
      setBigIntegerBackend2(_currentBackend);
    }
    return _currentImpl;
  }
  function setBigIntegerBackend3(backend) {
    _currentBackend = backend;
    setBigIntegerBackend(backend);
    setBigIntegerBackend2(backend);
  }
  function getWebCrypto() {
    const c = globalThis.crypto;
    if (!c || typeof c.getRandomValues !== "function") {
      throw new Error(
        "Web Crypto getRandomValues unavailable. Are you running in an environment without secure RNG?"
      );
    }
    return c;
  }
  function concat(...arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }
  function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }
  function toHex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      out += HEX_CHARS[b >>> 4];
      out += HEX_CHARS[b & 15];
    }
    return out;
  }
  function fromHex(hex) {
    const clean2 = hex.startsWith("0x") ? hex.slice(2) : hex;
    if (clean2.length % 2 !== 0) {
      throw new Error(`Invalid hex: odd length ${clean2.length}`);
    }
    const out = new Uint8Array(clean2.length / 2);
    for (let i = 0; i < out.length; i++) {
      const hi = parseHexNibble(clean2.charCodeAt(i * 2));
      const lo = parseHexNibble(clean2.charCodeAt(i * 2 + 1));
      out[i] = hi << 4 | lo;
    }
    return out;
  }
  function parseHexNibble(c) {
    if (c >= 48 && c <= 57) return c - 48;
    if (c >= 97 && c <= 102) return c - 97 + 10;
    if (c >= 65 && c <= 70) return c - 65 + 10;
    throw new Error(`Invalid hex character: 0x${c.toString(16).padStart(2, "0")}`);
  }
  function toBase64(bytes) {
    let binary = "";
    const chunk = 32768;
    for (let i = 0; i < bytes.length; i += chunk) {
      const slice = bytes.subarray(i, Math.min(i + chunk, bytes.length));
      binary += String.fromCharCode(...slice);
    }
    return btoa(binary);
  }
  function fromBase64(b64) {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }
  function fromUtf8(s) {
    return utf8Encoder.encode(s);
  }
  function toUtf8(bytes) {
    return utf8Decoder.decode(bytes);
  }
  function fromLatin1(s) {
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 255;
    return out;
  }
  function toLatin1(bytes) {
    let out = "";
    const chunk = 32768;
    for (let i = 0; i < bytes.length; i += chunk) {
      const slice = bytes.subarray(i, Math.min(i + chunk, bytes.length));
      out += String.fromCharCode(...slice);
    }
    return out;
  }
  function readUInt32BE(bytes, offset = 0) {
    if (offset + 4 > bytes.length) {
      throw new RangeError(`readUInt32BE: out of range (offset=${offset}, length=${bytes.length})`);
    }
    return (bytes[offset] << 24 | bytes[offset + 1] << 16 | bytes[offset + 2] << 8 | bytes[offset + 3]) >>> 0;
  }
  function writeUInt32BE(value, target, offset = 0) {
    if (offset + 4 > target.length) {
      throw new RangeError(`writeUInt32BE: out of range (offset=${offset}, length=${target.length})`);
    }
    target[offset] = value >>> 24 & 255;
    target[offset + 1] = value >>> 16 & 255;
    target[offset + 2] = value >>> 8 & 255;
    target[offset + 3] = value & 255;
  }
  function linebrk(str, maxLen) {
    let out = "";
    let i = 0;
    while (i + maxLen < str.length) {
      out += `${str.substring(i, i + maxLen)}
`;
      i += maxLen;
    }
    return out + str.substring(i);
  }
  function trimSurroundingText(data, opening, closing) {
    let start = 0;
    let end = data.length;
    const openIdx = data.indexOf(opening);
    const closeIdx = openIdx >= 0 ? data.indexOf(closing, openIdx) : -1;
    if (openIdx >= 0 && closeIdx >= 0) {
      const secondOpen = data.indexOf(opening, closeIdx + closing.length);
      if (secondOpen >= 0) {
        throw new Error(`multiple ${opening} blocks \u2014 refusing ambiguous input`);
      }
    }
    if (openIdx >= 0) start = openIdx + opening.length;
    if (closeIdx >= 0) end = closeIdx;
    return data.substring(start, end);
  }
  function tagName(tag) {
    switch (tag) {
      case Tag.INTEGER:
        return "INTEGER";
      case Tag.BIT_STRING:
        return "BIT STRING";
      case Tag.OCTET_STRING:
        return "OCTET STRING";
      case Tag.NULL:
        return "NULL";
      case Tag.OBJECT_IDENTIFIER:
        return "OBJECT IDENTIFIER";
      case Tag.SEQUENCE:
        return "SEQUENCE";
      default:
        return `tag 0x${tag.toString(16).padStart(2, "0")}`;
    }
  }
  function decodeOid(bytes) {
    if (bytes.length === 0) {
      throw new Error("DerReader: empty OID");
    }
    let i = 0;
    let combined = 0;
    let b;
    do {
      if (i >= bytes.length) throw new Error("DerReader: truncated OID");
      b = bytes[i++];
      combined = combined * 128 + (b & 127);
    } while ((b & 128) !== 0);
    const arcs = [];
    if (combined < 40) {
      arcs.push(0, combined);
    } else if (combined < 80) {
      arcs.push(1, combined - 40);
    } else {
      arcs.push(2, combined - 80);
    }
    while (i < bytes.length) {
      let arc = 0;
      do {
        if (i >= bytes.length) throw new Error("DerReader: truncated OID arc");
        b = bytes[i++];
        arc = arc * 128 + (b & 127);
      } while ((b & 128) !== 0);
      arcs.push(arc);
    }
    return arcs.join(".");
  }
  function encodeLength(n) {
    if (n < 0) throw new Error(`DerWriter: negative length ${n}`);
    if (n < 128) return new Uint8Array([n]);
    const bytes = [];
    let temp = n;
    while (temp > 0) {
      bytes.unshift(temp & 255);
      temp = Math.floor(temp / 256);
    }
    if (bytes.length > 127) {
      throw new Error(`DerWriter: length ${n} exceeds DER limits`);
    }
    return new Uint8Array([128 | bytes.length, ...bytes]);
  }
  function encodeSmallInteger(n) {
    if (n < 0) throw new Error(`DerWriter: negative integers not supported (got ${n})`);
    if (n === 0) return new Uint8Array([0]);
    if (!Number.isSafeInteger(n)) {
      throw new Error(`DerWriter: integer ${n} not a safe integer`);
    }
    const bytes = [];
    let temp = n;
    while (temp > 0) {
      bytes.unshift(temp & 255);
      temp = Math.floor(temp / 256);
    }
    if (bytes[0] & 128) bytes.unshift(0);
    return new Uint8Array(bytes);
  }
  function normalizePositiveInteger(value) {
    let i = 0;
    while (i < value.length - 1 && value[i] === 0 && (value[i + 1] & 128) === 0) {
      i++;
    }
    const trimmed = value.subarray(i);
    if (trimmed.length > 0 && trimmed[0] & 128) {
      const out = new Uint8Array(trimmed.length + 1);
      out[0] = 0;
      out.set(trimmed, 1);
      return out;
    }
    return trimmed.length === 0 ? new Uint8Array([0]) : trimmed;
  }
  function encodeOid(oid) {
    const arcs = oid.split(".").map((s) => {
      const n = Number(s);
      if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
        throw new Error(`DerWriter: invalid OID arc "${s}"`);
      }
      return n;
    });
    if (arcs.length < 2) {
      throw new Error(`DerWriter: OID must have at least 2 arcs, got "${oid}"`);
    }
    const arc0 = arcs[0];
    const arc1 = arcs[1];
    if (arc0 > 2 || arc0 < 2 && arc1 >= 40) {
      throw new Error(`DerWriter: invalid leading arcs ${arc0}.${arc1}`);
    }
    const out = [];
    encodeBase128Into(arc0 * 40 + arc1, out);
    for (let i = 2; i < arcs.length; i++) {
      encodeBase128Into(arcs[i], out);
    }
    return new Uint8Array(out);
  }
  function encodeBase128Into(n, out) {
    if (n === 0) {
      out.push(0);
      return;
    }
    const bytes = [];
    let temp = n;
    while (temp > 0) {
      bytes.unshift(temp & 127);
      temp = Math.floor(temp / 128);
    }
    for (let i = 0; i < bytes.length - 1; i++) {
      bytes[i] = bytes[i] | 128;
    }
    out.push(...bytes);
  }
  function encodePem(body, opening, closing, lineLength = 64) {
    return `${opening}
${linebrk(toBase64(body), lineLength)}
${closing}`;
  }
  function decodePem(text, opening, closing) {
    const trimmed = trimSurroundingText(text, opening, closing).replace(/\s+/g, "");
    return fromBase64(trimmed);
  }
  function resolveBytes(data, options, opening, closing) {
    if (options.type === "der") {
      if (data instanceof Uint8Array) return data;
      throw new Error("Unsupported key format");
    }
    if (data instanceof Uint8Array) {
      return decodePem(new TextDecoder().decode(data), opening, closing);
    }
    if (typeof data === "string") {
      return decodePem(data, opening, closing);
    }
    throw new Error("Unsupported key format");
  }
  function pkcs8OidError(oid, kind) {
    if (oid === "1.2.840.113549.1.1.10") {
      return new Error(
        `PKCS#8 ${kind} key: RSASSA-PSS-only keys (1.2.840.113549.1.1.10) are not supported; expected rsaEncryption`
      );
    }
    if (oid === "1.2.840.113549.1.1.7") {
      return new Error(
        `PKCS#8 ${kind} key: RSAES-OAEP-only keys (1.2.840.113549.1.1.7) are not supported; expected rsaEncryption`
      );
    }
    return new Error(
      `PKCS#8 ${kind} key: unsupported algorithm OID ${oid}; expected rsaEncryption (1.2.840.113549.1.1.1)`
    );
  }
  function formatParse(format) {
    const parts = format.split("-");
    let keyType = "private";
    const keyOpt = { type: "default" };
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i];
      if (p === "public" || p === "private") keyType = p;
      else if (p === "pem" || p === "der") keyOpt.type = p;
    }
    return { scheme: parts[0] ?? "", keyType, keyOpt };
  }
  function detectAndImport(key, data, format) {
    if (!format) {
      for (const scheme of Object.values(FORMATS)) {
        if (scheme.autoImport?.(key, data)) return true;
      }
      return false;
    }
    const fmt = formatParse(format);
    const provider = FORMATS[fmt.scheme];
    if (!provider) throw new Error("Unsupported key format");
    if (fmt.keyType === "private") {
      if (!provider.privateImport) throw new Error(`Format ${fmt.scheme} has no privateImport`);
      provider.privateImport(key, data, fmt.keyOpt);
    } else {
      if (!provider.publicImport) throw new Error(`Format ${fmt.scheme} has no publicImport`);
      provider.publicImport(key, data, fmt.keyOpt);
    }
    return true;
  }
  function detectAndExport(key, format) {
    if (!format) return void 0;
    const fmt = formatParse(format);
    const provider = FORMATS[fmt.scheme];
    if (!provider) throw new Error("Unsupported key format");
    if (fmt.keyType === "private") {
      if (!key.isPrivate()) throw new Error("This is not private key");
      if (!provider.privateExport) throw new Error(`Format ${fmt.scheme} has no privateExport`);
      return provider.privateExport(key, fmt.keyOpt);
    }
    if (!key.isPublic()) throw new Error("This is not public key");
    if (!provider.publicExport) throw new Error(`Format ${fmt.scheme} has no publicExport`);
    return provider.publicExport(key, fmt.keyOpt);
  }
  function mgf1(seed, maskLength, hash, backend) {
    const hLen = DIGEST_LENGTH[hash];
    const count = Math.ceil(maskLength / hLen);
    const out = new Uint8Array(hLen * count);
    const counter = new Uint8Array(4);
    for (let i = 0; i < count; i++) {
      writeUInt32BE(i, counter, 0);
      const h = backend.digest(hash, concat(seed, counter));
      out.set(h, i * hLen);
    }
    return out.subarray(0, maskLength);
  }
  function allowedHashes(env) {
    return SUPPORTED_HASH_ALGORITHMS[env] ?? NODE_HASHES;
  }
  function makeDefaultOptions(environment) {
    return {
      signingScheme: DEFAULT_SIGNING_SCHEME,
      signingSchemeOptions: { hash: "sha256" },
      encryptionScheme: DEFAULT_ENCRYPTION_SCHEME,
      encryptionSchemeOptions: { hash: "sha1" },
      environment,
      // Mirrors the per-bundle default flipped by the entry module
      // (index.browser.ts switches to 'native' at load; index.node.ts leaves
      // 'jsbn'). Stored on ResolvedOptions so callers can read the active
      // setting back off the NodeRSA instance.
      bigIntImpl: environment === "browser" ? "native" : "jsbn"
    };
  }
  function applyOptions(target, options) {
    if (options.bigIntImpl) {
      setBigIntegerImpl(options.bigIntImpl);
      target.bigIntImpl = options.bigIntImpl;
    }
    if (options.environment) {
      if (options.environment !== target.environment && !warnedEnvironment) {
        console.warn(
          "NodeRSA: setOptions({environment}) is deprecated. Build-time platform conditions decide the runtime; the option now only forces the pure-JS engine path."
        );
        warnedEnvironment = true;
      }
      target.environment = options.environment;
    }
    if (options.signingScheme !== void 0) {
      if (typeof options.signingScheme === "string") {
        const parts = options.signingScheme.toLowerCase().split("-");
        if (parts.length === 1) {
          if (NODE_HASHES.includes(parts[0])) {
            target.signingSchemeOptions = { hash: parts[0] };
            target.signingScheme = DEFAULT_SIGNING_SCHEME;
          } else {
            target.signingScheme = parts[0];
            target.signingSchemeOptions = {};
          }
        } else {
          target.signingScheme = parts[0];
          target.signingSchemeOptions = { hash: parts[1] };
        }
      } else {
        const obj = options.signingScheme;
        target.signingScheme = obj.scheme ?? DEFAULT_SIGNING_SCHEME;
        const { scheme: _scheme, ...rest } = obj;
        target.signingSchemeOptions = rest;
      }
      if (!SCHEMES[target.signingScheme]?.isSignature) {
        throw new Error("Unsupported signing scheme");
      }
      if (target.signingSchemeOptions.hash && !allowedHashes(target.environment).includes(target.signingSchemeOptions.hash)) {
        throw new Error(`Unsupported hashing algorithm for ${target.environment} environment`);
      }
      if (target.signingSchemeOptions.hash && (target.signingSchemeOptions.hash === "md4" || target.signingSchemeOptions.hash === "md5")) {
        console.warn(
          `node-rsa: ${target.signingSchemeOptions.hash} is cryptographically broken for signatures; use sha256 or stronger`
        );
      }
    }
    if (options.encryptionScheme !== void 0) {
      if (typeof options.encryptionScheme === "string") {
        target.encryptionScheme = options.encryptionScheme.toLowerCase();
        target.encryptionSchemeOptions = {};
      } else {
        const obj = options.encryptionScheme;
        target.encryptionScheme = obj.scheme ?? DEFAULT_ENCRYPTION_SCHEME;
        const { scheme: _scheme, ...rest } = obj;
        target.encryptionSchemeOptions = rest;
      }
      if (!SCHEMES[target.encryptionScheme]?.isEncryption) {
        throw new Error("Unsupported encryption scheme");
      }
      if (target.encryptionSchemeOptions.hash && !allowedHashes(target.environment).includes(target.encryptionSchemeOptions.hash)) {
        throw new Error(`Unsupported hashing algorithm for ${target.environment} environment`);
      }
    }
  }
  function readBigEndianUInt(buf) {
    let n = 0;
    for (let i = 0; i < buf.length; i++) n = n * 256 + buf[i];
    return n;
  }
  function bootstrap(config) {
    internal = config;
    setBigIntegerBackend3(config.backend);
  }
  function getInternal() {
    if (!internal) {
      throw new Error(
        "NodeRSA: backend not initialized. Import the package via its main entry, not by deep-importing internals."
      );
    }
    return internal;
  }
  function encodeBytes(bytes, encoding) {
    switch (encoding) {
      case "hex":
        return toHex(bytes);
      case "base64":
        return toBase64(bytes);
      case "utf8":
        return toUtf8(bytes);
      case "binary":
      case "latin1":
        return toLatin1(bytes);
      default:
        return toBase64(bytes);
    }
  }
  function decodeBytes(s, encoding) {
    switch (encoding) {
      case "hex": {
        if (s.length % 2 !== 0) throw new Error("Invalid hex string");
        const out = new Uint8Array(s.length / 2);
        for (let i = 0; i < out.length; i++)
          out[i] = Number.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
      }
      case "utf8":
        return fromUtf8(s);
      case "binary":
      case "latin1":
        return fromLatin1(s);
      case void 0:
      case null:
      case "buffer":
      case "base64":
        return fromBase64(s);
      default:
        return fromBase64(s);
    }
  }
  var _backend, DB, DM, DV, BI_FP, FV, F1, F2, BI_RM, BI_RC, BigInteger, Classic, Montgomery, Barrett, NullExp, lowprimes, lplim, _backend2, ZERO_BI, ONE_BI, TWO_BI, SMALL_PRIMES, SMALL_PRIMES_BI, BigInteger2, BigInteger3, _currentImpl, _currentBackend, HASHES, webBackend, HEX_CHARS, utf8Encoder, utf8Decoder, componentsFormat, PRIVATE_OPENING, PRIVATE_CLOSING, opensshFormat, SshReader, SshWriter, OID, Tag, DerReader, DerWriter, PRIVATE_OPENING2, PRIVATE_CLOSING2, PUBLIC_OPENING, PUBLIC_CLOSING, pkcs1Format, PRIVATE_OPENING3, PRIVATE_CLOSING3, PUBLIC_OPENING2, PUBLIC_CLOSING2, pkcs8Format, FORMATS, DIGEST_LENGTH, DEFAULT_HASH, OaepScheme, oaepScheme, RSA_NO_PADDING, SIGN_INFO_HEAD, DEFAULT_HASH2, Pkcs1Scheme, pkcs1Scheme, DEFAULT_HASH3, DEFAULT_SALT_LENGTH, PssScheme, pssScheme, SCHEMES, NODE_HASHES, SUPPORTED_HASH_ALGORITHMS, DEFAULT_ENCRYPTION_SCHEME, DEFAULT_SIGNING_SCHEME, EXPORT_FORMAT_ALIASES, warnedEnvironment, JsEngine, warnedSmallKey, RSAKey, internal, NodeRSA, index_browser_default;
  var init_index_browser = __esm({
    "node_modules/node-rsa/dist/index.browser.js"() {
      init_legacy();
      init_sha2();
      DB = 28;
      DM = (1 << DB) - 1;
      DV = 1 << DB;
      BI_FP = 52;
      FV = 2 ** BI_FP;
      F1 = BI_FP - DB;
      F2 = 2 * DB - BI_FP;
      BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
      BI_RC = [];
      {
        let rr = "0".charCodeAt(0);
        for (let vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
        rr = "a".charCodeAt(0);
        for (let vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
        rr = "A".charCodeAt(0);
        for (let vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
      }
      BigInteger = class _BigInteger {
        /** @internal */
        t = 0;
        /** @internal */
        s = 0;
        // Mirror legacy `this.DB`/`this.DM`/etc. access patterns
        /** @internal */
        DB = DB;
        /** @internal */
        DM = DM;
        /** @internal */
        DV = DV;
        /** @internal */
        FV = FV;
        /** @internal */
        F1 = F1;
        /** @internal */
        F2 = F2;
        static ZERO;
        static ONE;
        /** @internal */
        static int2char = int2char;
        constructor(a, b, unsigned) {
          if (a == null) return;
          if (typeof a === "number") {
            this.fromNumber(a, b);
          } else if (a instanceof Uint8Array) {
            this.fromBuffer(a);
          } else if (typeof a === "string") {
            this.fromString(a, b, unsigned);
          } else if (Array.isArray(a)) {
            this.fromByteArray(a, unsigned);
          }
        }
        // am3: multiply-accumulate (digit-base 2^28)
        /** @internal */
        am(i, x, w, j, c, n) {
          const xl = x & 16383;
          const xh = x >> 14;
          while (--n >= 0) {
            let l = this[i] & 16383;
            const h = this[i++] >> 14;
            const m = xh * l + h * xl;
            l = xl * l + ((m & 16383) << 14) + w[j] + c;
            c = (l >> 28) + (m >> 14) + xh * h;
            w[j++] = l & 268435455;
          }
          return c;
        }
        // protected: digit/byte initialisation
        /** @internal */
        copyTo(r) {
          for (let i = this.t - 1; i >= 0; --i) r[i] = this[i];
          r.t = this.t;
          r.s = this.s;
        }
        /** @internal */
        fromInt(x) {
          this.t = 1;
          this.s = x < 0 ? -1 : 0;
          if (x > 0) this[0] = x;
          else if (x < -1) this[0] = x + DV;
          else this.t = 0;
        }
        /** @internal */
        fromString(data, radix, unsigned) {
          let k;
          switch (radix) {
            case 2:
              k = 1;
              break;
            case 4:
              k = 2;
              break;
            case 8:
              k = 3;
              break;
            case 16:
              k = 4;
              break;
            case 32:
              k = 5;
              break;
            case 256:
              k = 8;
              break;
            default:
              this.fromRadix(data, radix);
              return;
          }
          this.t = 0;
          this.s = 0;
          const dataAny = data;
          let i = dataAny.length;
          let mi = false;
          let sh = 0;
          while (--i >= 0) {
            const x = k === 8 ? dataAny[i] & 255 : intAt(data, i);
            if (x < 0) {
              if (dataAny.charAt && dataAny.charAt(i) === "-") mi = true;
              continue;
            }
            mi = false;
            if (sh === 0) this[this.t++] = x;
            else if (sh + k > this.DB) {
              this[this.t - 1] = (this[this.t - 1] | (x & (1 << this.DB - sh) - 1) << sh) >>> 0;
              this[this.t++] = x >> this.DB - sh;
            } else {
              this[this.t - 1] = (this[this.t - 1] | x << sh) >>> 0;
            }
            sh += k;
            if (sh >= this.DB) sh -= this.DB;
          }
          if (!unsigned && k === 8 && (dataAny[0] & 128) !== 0) {
            this.s = -1;
            if (sh > 0)
              this[this.t - 1] = (this[this.t - 1] | (1 << this.DB - sh) - 1 << sh) >>> 0;
          }
          this.clamp();
          if (mi) _BigInteger.ZERO.subTo(this, this);
        }
        /** @internal */
        fromByteArray(a, unsigned) {
          this.fromString(a, 256, unsigned);
        }
        /** @internal */
        fromBuffer(a) {
          this.fromString(a, 256, true);
        }
        /** @internal */
        clamp() {
          const c = this.s & this.DM;
          while (this.t > 0 && this[this.t - 1] === c) --this.t;
        }
        // arithmetic on internal digits
        /** @internal */
        dlShiftTo(n, r) {
          let i;
          for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
          for (i = n - 1; i >= 0; --i) r[i] = 0;
          r.t = this.t + n;
          r.s = this.s;
        }
        /** @internal */
        drShiftTo(n, r) {
          for (let i = n; i < this.t; ++i) r[i - n] = this[i];
          r.t = Math.max(this.t - n, 0);
          r.s = this.s;
        }
        /** @internal */
        lShiftTo(n, r) {
          const bs = n % this.DB;
          const cbs = this.DB - bs;
          const bm = (1 << cbs) - 1;
          const ds = Math.floor(n / this.DB);
          let c = this.s << bs & this.DM;
          let i;
          for (i = this.t - 1; i >= 0; --i) {
            r[i + ds + 1] = this[i] >> cbs | c;
            c = (this[i] & bm) << bs;
          }
          for (i = ds - 1; i >= 0; --i) r[i] = 0;
          r[ds] = c;
          r.t = this.t + ds + 1;
          r.s = this.s;
          r.clamp();
        }
        /** @internal */
        rShiftTo(n, r) {
          r.s = this.s;
          const ds = Math.floor(n / this.DB);
          if (ds >= this.t) {
            r.t = 0;
            return;
          }
          const bs = n % this.DB;
          const cbs = this.DB - bs;
          const bm = (1 << bs) - 1;
          r[0] = this[ds] >> bs;
          for (let i = ds + 1; i < this.t; ++i) {
            r[i - ds - 1] = (r[i - ds - 1] ?? 0) | (this[i] & bm) << cbs;
            r[i - ds] = this[i] >> bs;
          }
          if (bs > 0) r[this.t - ds - 1] = (r[this.t - ds - 1] ?? 0) | (this.s & bm) << cbs;
          r.t = this.t - ds;
          r.clamp();
        }
        /** @internal */
        subTo(a, r) {
          let i = 0;
          let c = 0;
          const m = Math.min(a.t, this.t);
          while (i < m) {
            c += this[i] - a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
          }
          if (a.t < this.t) {
            c -= a.s;
            while (i < this.t) {
              c += this[i];
              r[i++] = c & this.DM;
              c >>= this.DB;
            }
            c += this.s;
          } else {
            c += this.s;
            while (i < a.t) {
              c -= a[i];
              r[i++] = c & this.DM;
              c >>= this.DB;
            }
            c -= a.s;
          }
          r.s = c < 0 ? -1 : 0;
          if (c < -1) r[i++] = this.DV + c;
          else if (c > 0) r[i++] = c;
          r.t = i;
          r.clamp();
        }
        /** @internal */
        multiplyTo(a, r) {
          const x = this.abs();
          const y = a.abs();
          let i = x.t;
          r.t = i + y.t;
          while (--i >= 0) r[i] = 0;
          for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
          r.s = 0;
          r.clamp();
          if (this.s !== a.s) _BigInteger.ZERO.subTo(r, r);
        }
        /** @internal */
        squareTo(r) {
          const x = this.abs();
          let i = r.t = 2 * x.t;
          while (--i >= 0) r[i] = 0;
          for (i = 0; i < x.t - 1; ++i) {
            const c = x.am(i, x[i], r, 2 * i, 0, 1);
            if ((r[i + x.t] = (r[i + x.t] ?? 0) + x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
              r[i + x.t] = r[i + x.t] - x.DV;
              r[i + x.t + 1] = 1;
            }
          }
          if (r.t > 0) r[r.t - 1] = (r[r.t - 1] ?? 0) + x.am(i, x[i], r, 2 * i, 0, 1);
          r.s = 0;
          r.clamp();
        }
        /** @internal */
        divRemTo(m, q, r) {
          const pm = m.abs();
          if (pm.t <= 0) return;
          const pt = this.abs();
          if (pt.t < pm.t) {
            if (q != null) q.fromInt(0);
            if (r != null) this.copyTo(r);
            return;
          }
          if (r == null) r = nbi();
          const y = nbi();
          const ts = this.s;
          const ms = m.s;
          const nsh = this.DB - nbits(pm[pm.t - 1]);
          if (nsh > 0) {
            pm.lShiftTo(nsh, y);
            pt.lShiftTo(nsh, r);
          } else {
            pm.copyTo(y);
            pt.copyTo(r);
          }
          const ys = y.t;
          const y0 = y[ys - 1];
          if (y0 === 0) return;
          const yt = y0 * (1 << this.F1) + (ys > 1 ? y[ys - 2] >> this.F2 : 0);
          const d1 = this.FV / yt;
          const d2 = (1 << this.F1) / yt;
          const e = 1 << this.F2;
          let i = r.t;
          let j = i - ys;
          const t = q == null ? nbi() : q;
          y.dlShiftTo(j, t);
          if (r.compareTo(t) >= 0) {
            r[r.t++] = 1;
            r.subTo(t, r);
          }
          _BigInteger.ONE.dlShiftTo(ys, t);
          t.subTo(y, y);
          while (y.t < ys) y[y.t++] = 0;
          while (--j >= 0) {
            let qd = r[--i] === y0 ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
            if ((r[i] = r[i] + y.am(0, qd, r, j, 0, ys)) < qd) {
              y.dlShiftTo(j, t);
              r.subTo(t, r);
              while (r[i] < --qd) r.subTo(t, r);
            }
          }
          if (q != null) {
            r.drShiftTo(ys, q);
            if (ts !== ms) _BigInteger.ZERO.subTo(q, q);
          }
          r.t = ys;
          r.clamp();
          if (nsh > 0) r.rShiftTo(nsh, r);
          if (ts < 0) _BigInteger.ZERO.subTo(r, r);
        }
        /** @internal */
        invDigit() {
          if (this.t < 1) return 0;
          const x = this[0];
          if ((x & 1) === 0) return 0;
          let y = x & 3;
          y = y * (2 - (x & 15) * y) & 15;
          y = y * (2 - (x & 255) * y) & 255;
          y = y * (2 - ((x & 65535) * y & 65535)) & 65535;
          y = y * (2 - x * y % this.DV) % this.DV;
          return y > 0 ? this.DV - y : -y;
        }
        isEven() {
          return ((this.t > 0 ? this[0] & 1 : this.s) & 1) === 0;
        }
        /** @internal */
        exp(e, z) {
          if (e > 4294967295 || e < 1) return _BigInteger.ONE;
          let r = nbi();
          let r2 = nbi();
          const g = z.convert(this);
          let i = nbits(e) - 1;
          g.copyTo(r);
          while (--i >= 0) {
            z.sqrTo(r, r2);
            if ((e & 1 << i) > 0) z.mulTo(r2, g, r);
            else {
              const tmp = r;
              r = r2;
              r2 = tmp;
            }
          }
          return z.revert(r);
        }
        // public arithmetic & comparisons
        toString(b) {
          if (this.s < 0) return `-${this.negate().toString(b)}`;
          let k;
          if (b === 16) k = 4;
          else if (b === 8) k = 3;
          else if (b === 2) k = 1;
          else if (b === 32) k = 5;
          else if (b === 4) k = 2;
          else return this.toRadix(b);
          const km = (1 << k) - 1;
          let d;
          let m = false;
          let r = "";
          let i = this.t;
          let p = this.DB - i * this.DB % k;
          if (i-- > 0) {
            if (p < this.DB && (d = this[i] >> p) > 0) {
              m = true;
              r = int2char(d);
            }
            while (i >= 0) {
              if (p < k) {
                d = (this[i] & (1 << p) - 1) << k - p;
                d |= this[--i] >> (p += this.DB - k);
              } else {
                d = this[i] >> (p -= k) & km;
                if (p <= 0) {
                  p += this.DB;
                  --i;
                }
              }
              if (d > 0) m = true;
              if (m) r += int2char(d);
            }
          }
          return m ? r : "0";
        }
        /** @internal */
        negate() {
          const r = nbi();
          _BigInteger.ZERO.subTo(this, r);
          return r;
        }
        abs() {
          return this.s < 0 ? this.negate() : this;
        }
        compareTo(a) {
          let r = this.s - a.s;
          if (r !== 0) return r;
          let i = this.t;
          r = i - a.t;
          if (r !== 0) return this.s < 0 ? -r : r;
          while (--i >= 0) if ((r = this[i] - a[i]) !== 0) return r;
          return 0;
        }
        bitLength() {
          if (this.t <= 0) return 0;
          return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ this.s & this.DM);
        }
        mod(a) {
          const r = nbi();
          this.abs().divRemTo(a, null, r);
          if (this.s < 0 && r.compareTo(_BigInteger.ZERO) > 0) a.subTo(r, r);
          return r;
        }
        modPowInt(e, m) {
          const z = e < 256 || m.isEven() ? new Classic(m) : new Montgomery(m);
          return this.exp(e, z);
        }
        // extended functions
        /** @internal */
        clone() {
          const r = nbi();
          this.copyTo(r);
          return r;
        }
        /** @internal */
        intValue() {
          if (this.s < 0) {
            if (this.t === 1) return this[0] - this.DV;
            if (this.t === 0) return -1;
          } else if (this.t === 1) return this[0];
          else if (this.t === 0) return 0;
          return (this[1] & (1 << 32 - this.DB) - 1) << this.DB | this[0];
        }
        /** @internal */
        byteValue() {
          return this.t === 0 ? this.s : this[0] << 24 >> 24;
        }
        /** @internal */
        shortValue() {
          return this.t === 0 ? this.s : this[0] << 16 >> 16;
        }
        /** @internal */
        chunkSize(r) {
          return Math.floor(Math.LN2 * this.DB / Math.log(r));
        }
        signum() {
          if (this.s < 0) return -1;
          if (this.t <= 0 || this.t === 1 && this[0] <= 0) return 0;
          return 1;
        }
        /** @internal */
        toRadix(b) {
          const base = b ?? 10;
          if (this.signum() === 0 || base < 2 || base > 36) return "0";
          const cs = this.chunkSize(base);
          const a = base ** cs;
          const d = nbv(a);
          const y = nbi();
          const z = nbi();
          let r = "";
          this.divRemTo(d, y, z);
          while (y.signum() > 0) {
            r = (a + z.intValue()).toString(base).slice(1) + r;
            y.divRemTo(d, y, z);
          }
          return z.intValue().toString(base) + r;
        }
        /** @internal */
        fromRadix(s, b) {
          this.fromInt(0);
          const base = b ?? 10;
          const cs = this.chunkSize(base);
          const d = base ** cs;
          let mi = false;
          let j = 0;
          let w = 0;
          for (let i = 0; i < s.length; ++i) {
            const x = intAt(s, i);
            if (x < 0) {
              if (s.charAt(i) === "-" && this.signum() === 0) mi = true;
              continue;
            }
            w = base * w + x;
            if (++j >= cs) {
              this.dMultiply(d);
              this.dAddOffset(w, 0);
              j = 0;
              w = 0;
            }
          }
          if (j > 0) {
            this.dMultiply(base ** j);
            this.dAddOffset(w, 0);
          }
          if (mi) _BigInteger.ZERO.subTo(this, this);
        }
        /** @internal */
        fromNumber(a, b) {
          if (typeof b === "number") {
            if (a < 2) this.fromInt(1);
            else {
              this.fromNumber(a);
              if (!this.testBit(a - 1)) {
                this.bitwiseTo(_BigInteger.ONE.shiftLeft(a - 1), op_or, this);
              }
              if (this.isEven()) this.dAddOffset(1, 0);
              while (!this.isProbablePrime(b)) {
                this.dAddOffset(2, 0);
                if (this.bitLength() > a) this.subTo(_BigInteger.ONE.shiftLeft(a - 1), this);
              }
            }
          } else {
            const x = getBackend().randomBytes((a >> 3) + 1);
            const t = a & 7;
            const bytes = new Uint8Array(x);
            if (t > 0) bytes[0] = bytes[0] & (1 << t) - 1;
            else bytes[0] = 0;
            this.fromByteArray(Array.from(bytes));
          }
        }
        /** @internal */
        toByteArray() {
          let i = this.t;
          const r = [];
          r[0] = this.s;
          let p = this.DB - i * this.DB % 8;
          let d;
          let k = 0;
          if (i-- > 0) {
            if (p < this.DB && (d = this[i] >> p) !== (this.s & this.DM) >> p) {
              r[k++] = d | this.s << this.DB - p;
            }
            while (i >= 0) {
              if (p < 8) {
                d = (this[i] & (1 << p) - 1) << 8 - p;
                d |= this[--i] >> (p += this.DB - 8);
              } else {
                d = this[i] >> (p -= 8) & 255;
                if (p <= 0) {
                  p += this.DB;
                  --i;
                }
              }
              if ((d & 128) !== 0) d |= -256;
              if (k === 0 && (this.s & 128) !== (d & 128)) ++k;
              if (k > 0 || d !== this.s) r[k++] = d;
            }
          }
          return r;
        }
        /**
         * Return a Uint8Array of this integer in big-endian unsigned form.
         *
         * - `trimOrSize === true`: drop a leading 0x00 sign byte if present.
         * - `trimOrSize` is a positive integer: left-pad or trim leading zeros to
         *   produce exactly `trimOrSize` bytes. Returns null if trimming would
         *   discard a non-zero byte (i.e., the value doesn't fit).
         * - Otherwise: return the raw two's-complement byte array with possible
         *   leading 0x00 sign byte.
         */
        toBuffer(trimOrSize) {
          let res = Uint8Array.from(this.toByteArray().map((b) => b & 255));
          if (trimOrSize === true && res.length > 0 && res[0] === 0) {
            res = res.subarray(1);
          } else if (typeof trimOrSize === "number") {
            if (res.length > trimOrSize) {
              const excess = res.length - trimOrSize;
              for (let i = 0; i < excess; i++) {
                if (res[i] !== 0) return null;
              }
              return res.subarray(excess).slice();
            }
            if (res.length < trimOrSize) {
              const padded = new Uint8Array(trimOrSize);
              padded.set(res, trimOrSize - res.length);
              return padded;
            }
          }
          return res.slice();
        }
        /** @internal */
        equals(a) {
          return this.compareTo(a) === 0;
        }
        /** @internal */
        min(a) {
          return this.compareTo(a) < 0 ? this : a;
        }
        /** @internal */
        max(a) {
          return this.compareTo(a) > 0 ? this : a;
        }
        /** @internal */
        bitwiseTo(a, op, r) {
          let i;
          let f;
          const m = Math.min(a.t, this.t);
          for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
          if (a.t < this.t) {
            f = a.s & this.DM;
            for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
            r.t = this.t;
          } else {
            f = this.s & this.DM;
            for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
            r.t = a.t;
          }
          r.s = op(this.s, a.s);
          r.clamp();
        }
        /** @internal */
        and(a) {
          const r = nbi();
          this.bitwiseTo(a, op_and, r);
          return r;
        }
        /** @internal */
        or(a) {
          const r = nbi();
          this.bitwiseTo(a, op_or, r);
          return r;
        }
        /** @internal */
        xor(a) {
          const r = nbi();
          this.bitwiseTo(a, op_xor, r);
          return r;
        }
        /** @internal */
        andNot(a) {
          const r = nbi();
          this.bitwiseTo(a, op_andnot, r);
          return r;
        }
        /** @internal */
        not() {
          const r = nbi();
          for (let i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
          r.t = this.t;
          r.s = ~this.s;
          return r;
        }
        shiftLeft(n) {
          const r = nbi();
          if (n < 0) this.rShiftTo(-n, r);
          else this.lShiftTo(n, r);
          return r;
        }
        shiftRight(n) {
          const r = nbi();
          if (n < 0) this.lShiftTo(-n, r);
          else this.rShiftTo(n, r);
          return r;
        }
        /** @internal */
        getLowestSetBit() {
          for (let i = 0; i < this.t; ++i) if (this[i] !== 0) return i * this.DB + lbit(this[i]);
          if (this.s < 0) return this.t * this.DB;
          return -1;
        }
        /** @internal */
        bitCount() {
          let r = 0;
          const x = this.s & this.DM;
          for (let i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
          return r;
        }
        testBit(n) {
          const j = Math.floor(n / this.DB);
          if (j >= this.t) return this.s !== 0;
          return (this[j] & 1 << n % this.DB) !== 0;
        }
        /** @internal */
        changeBit(n, op) {
          const r = _BigInteger.ONE.shiftLeft(n);
          this.bitwiseTo(r, op, r);
          return r;
        }
        /** @internal */
        setBit(n) {
          return this.changeBit(n, op_or);
        }
        /** @internal */
        clearBit(n) {
          return this.changeBit(n, op_andnot);
        }
        /** @internal */
        flipBit(n) {
          return this.changeBit(n, op_xor);
        }
        /** @internal */
        addTo(a, r) {
          let i = 0;
          let c = 0;
          const m = Math.min(a.t, this.t);
          while (i < m) {
            c += this[i] + a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
          }
          if (a.t < this.t) {
            c += a.s;
            while (i < this.t) {
              c += this[i];
              r[i++] = c & this.DM;
              c >>= this.DB;
            }
            c += this.s;
          } else {
            c += this.s;
            while (i < a.t) {
              c += a[i];
              r[i++] = c & this.DM;
              c >>= this.DB;
            }
            c += a.s;
          }
          r.s = c < 0 ? -1 : 0;
          if (c > 0) r[i++] = c;
          else if (c < -1) r[i++] = this.DV + c;
          r.t = i;
          r.clamp();
        }
        add(a) {
          const r = nbi();
          this.addTo(a, r);
          return r;
        }
        subtract(a) {
          const r = nbi();
          this.subTo(a, r);
          return r;
        }
        multiply(a) {
          const r = nbi();
          this.multiplyTo(a, r);
          return r;
        }
        square() {
          const r = nbi();
          this.squareTo(r);
          return r;
        }
        /** @internal */
        divide(a) {
          const r = nbi();
          this.divRemTo(a, r, null);
          return r;
        }
        /** @internal */
        remainder(a) {
          const r = nbi();
          this.divRemTo(a, null, r);
          return r;
        }
        divideAndRemainder(a) {
          const q = nbi();
          const r = nbi();
          this.divRemTo(a, q, r);
          return [q, r];
        }
        /** @internal */
        dMultiply(n) {
          this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
          ++this.t;
          this.clamp();
        }
        /** @internal */
        dAddOffset(n, w) {
          if (n === 0) return;
          while (this.t <= w) this[this.t++] = 0;
          this[w] = this[w] + n;
          while (this[w] >= this.DV) {
            this[w] = this[w] - this.DV;
            if (++w >= this.t) this[this.t++] = 0;
            this[w] = (this[w] ?? 0) + 1;
          }
        }
        /** @internal */
        pow(e) {
          return this.exp(e, new NullExp());
        }
        /** @internal */
        multiplyLowerTo(a, n, r) {
          let i = Math.min(this.t + a.t, n);
          r.s = 0;
          r.t = i;
          while (i > 0) r[--i] = 0;
          let j;
          for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
          for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
          r.clamp();
        }
        /** @internal */
        multiplyUpperTo(a, n, r) {
          --n;
          let i = r.t = this.t + a.t - n;
          r.s = 0;
          while (--i >= 0) r[i] = 0;
          for (i = Math.max(n - this.t, 0); i < a.t; ++i) {
            r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
          }
          r.clamp();
          r.drShiftTo(1, r);
        }
        modPow(e, m) {
          let i = e.bitLength();
          let k;
          let r = nbv(1);
          let z;
          if (i <= 0) return r;
          if (i < 18) k = 1;
          else if (i < 48) k = 3;
          else if (i < 144) k = 4;
          else if (i < 768) k = 5;
          else k = 6;
          if (i < 8) z = new Classic(m);
          else if (m.isEven()) z = new Barrett(m);
          else z = new Montgomery(m);
          const g = [];
          let n = 3;
          const k1 = k - 1;
          const km = (1 << k) - 1;
          g[1] = z.convert(this);
          if (k > 1) {
            const g2 = nbi();
            z.sqrTo(g[1], g2);
            while (n <= km) {
              g[n] = nbi();
              z.mulTo(g2, g[n - 2], g[n]);
              n += 2;
            }
          }
          let j = e.t - 1;
          let w;
          let is1 = true;
          let r2 = nbi();
          let t;
          i = nbits(e[j]) - 1;
          while (j >= 0) {
            if (i >= k1) w = e[j] >> i - k1 & km;
            else {
              w = (e[j] & (1 << i + 1) - 1) << k1 - i;
              if (j > 0) w |= e[j - 1] >> this.DB + i - k1;
            }
            n = k;
            while ((w & 1) === 0) {
              w >>= 1;
              --n;
            }
            if ((i -= n) < 0) {
              i += this.DB;
              --j;
            }
            if (is1) {
              g[w].copyTo(r);
              is1 = false;
            } else {
              while (n > 1) {
                z.sqrTo(r, r2);
                z.sqrTo(r2, r);
                n -= 2;
              }
              if (n > 0) z.sqrTo(r, r2);
              else {
                t = r;
                r = r2;
                r2 = t;
              }
              z.mulTo(r2, g[w], r);
            }
            while (j >= 0 && (e[j] & 1 << i) === 0) {
              z.sqrTo(r, r2);
              t = r;
              r = r2;
              r2 = t;
              if (--i < 0) {
                i = this.DB - 1;
                --j;
              }
            }
          }
          return z.revert(r);
        }
        gcd(a) {
          let x = this.s < 0 ? this.negate() : this.clone();
          let y = a.s < 0 ? a.negate() : a.clone();
          if (x.compareTo(y) < 0) {
            [x, y] = [y, x];
          }
          let i = x.getLowestSetBit();
          let g = y.getLowestSetBit();
          if (g < 0) return x;
          if (i < g) g = i;
          if (g > 0) {
            x.rShiftTo(g, x);
            y.rShiftTo(g, y);
          }
          while (x.signum() > 0) {
            if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
            if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
            if (x.compareTo(y) >= 0) {
              x.subTo(y, x);
              x.rShiftTo(1, x);
            } else {
              y.subTo(x, y);
              y.rShiftTo(1, y);
            }
          }
          if (g > 0) y.lShiftTo(g, y);
          return y;
        }
        /** @internal */
        modInt(n) {
          if (n <= 0) return 0;
          const d = this.DV % n;
          let r = this.s < 0 ? n - 1 : 0;
          if (this.t > 0) {
            if (d === 0) r = this[0] % n;
            else for (let i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
          }
          return r;
        }
        modInverse(m) {
          const ac = m.isEven();
          if (this.isEven() && ac || m.signum() === 0) return _BigInteger.ZERO;
          const u = m.clone();
          const v = this.clone();
          const a = nbv(1);
          const b = nbv(0);
          const c = nbv(0);
          const d = nbv(1);
          while (u.signum() !== 0) {
            while (u.isEven()) {
              u.rShiftTo(1, u);
              if (ac) {
                if (!a.isEven() || !b.isEven()) {
                  a.addTo(this, a);
                  b.subTo(m, b);
                }
                a.rShiftTo(1, a);
              } else if (!b.isEven()) b.subTo(m, b);
              b.rShiftTo(1, b);
            }
            while (v.isEven()) {
              v.rShiftTo(1, v);
              if (ac) {
                if (!c.isEven() || !d.isEven()) {
                  c.addTo(this, c);
                  d.subTo(m, d);
                }
                c.rShiftTo(1, c);
              } else if (!d.isEven()) d.subTo(m, d);
              d.rShiftTo(1, d);
            }
            if (u.compareTo(v) >= 0) {
              u.subTo(v, u);
              if (ac) a.subTo(c, a);
              b.subTo(d, b);
            } else {
              v.subTo(u, v);
              if (ac) c.subTo(a, c);
              d.subTo(b, d);
            }
          }
          if (v.compareTo(_BigInteger.ONE) !== 0) return _BigInteger.ZERO;
          if (d.compareTo(m) >= 0) return d.subtract(m);
          if (d.signum() < 0) d.addTo(m, d);
          else return d;
          if (d.signum() < 0) return d.add(m);
          return d;
        }
        isProbablePrime(t) {
          let i;
          const x = this.abs();
          if (x.t === 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
            for (i = 0; i < lowprimes.length; ++i) if (x[0] === lowprimes[i]) return true;
            return false;
          }
          if (x.isEven()) return false;
          i = 1;
          while (i < lowprimes.length) {
            let m = lowprimes[i];
            let j = i + 1;
            while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
            m = x.modInt(m);
            while (i < j) if (m % lowprimes[i++] === 0) return false;
          }
          return x.millerRabin(t);
        }
        /** @internal */
        millerRabin(t) {
          const n1 = this.subtract(_BigInteger.ONE);
          const k = n1.getLowestSetBit();
          if (k <= 0) return false;
          const r = n1.shiftRight(k);
          const two = nbv(2);
          const nMinus3 = n1.subtract(two);
          const byteLen = (this.bitLength() + 7 >> 3) + 1;
          for (let i = 0; i < t; ++i) {
            const rb = getBackend().randomBytes(byteLen);
            const a = new _BigInteger(rb).mod(nMinus3).add(two);
            let y = a.modPow(r, this);
            if (y.compareTo(_BigInteger.ONE) !== 0 && y.compareTo(n1) !== 0) {
              let j = 1;
              while (j++ < k && y.compareTo(n1) !== 0) {
                y = y.modPowInt(2, this);
                if (y.compareTo(_BigInteger.ONE) === 0) return false;
              }
              if (y.compareTo(n1) !== 0) return false;
            }
          }
          return true;
        }
      };
      Classic = class {
        constructor(m) {
          this.m = m;
        }
        m;
        convert(x) {
          if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
          return x;
        }
        revert(x) {
          return x;
        }
        reduce(x) {
          x.divRemTo(this.m, null, x);
        }
        mulTo(x, y, r) {
          x.multiplyTo(y, r);
          this.reduce(r);
        }
        sqrTo(x, r) {
          x.squareTo(r);
          this.reduce(r);
        }
      };
      Montgomery = class {
        m;
        mp;
        mpl;
        mph;
        um;
        mt2;
        constructor(m) {
          this.m = m;
          this.mp = m.invDigit();
          this.mpl = this.mp & 32767;
          this.mph = this.mp >> 15;
          this.um = (1 << m.DB - 15) - 1;
          this.mt2 = 2 * m.t;
        }
        convert(x) {
          const r = nbi();
          x.abs().dlShiftTo(this.m.t, r);
          r.divRemTo(this.m, null, r);
          if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
          return r;
        }
        revert(x) {
          const r = nbi();
          x.copyTo(r);
          this.reduce(r);
          return r;
        }
        reduce(x) {
          while (x.t <= this.mt2) x[x.t++] = 0;
          for (let i = 0; i < this.m.t; ++i) {
            let j = x[i] & 32767;
            const u0 = j * this.mpl + ((j * this.mph + (x[i] >> 15) * this.mpl & this.um) << 15) & x.DM;
            j = i + this.m.t;
            x[j] = (x[j] ?? 0) + this.m.am(0, u0, x, i, 0, this.m.t);
            while (x[j] >= x.DV) {
              x[j] = x[j] - x.DV;
              x[++j] = (x[j] ?? 0) + 1;
            }
          }
          x.clamp();
          x.drShiftTo(this.m.t, x);
          if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
        }
        mulTo(x, y, r) {
          x.multiplyTo(y, r);
          this.reduce(r);
        }
        sqrTo(x, r) {
          x.squareTo(r);
          this.reduce(r);
        }
      };
      Barrett = class {
        r2;
        q3;
        mu;
        m;
        constructor(m) {
          this.r2 = nbi();
          this.q3 = nbi();
          BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
          this.mu = this.r2.divide(m);
          this.m = m;
        }
        convert(x) {
          if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
          if (x.compareTo(this.m) < 0) return x;
          const r = nbi();
          x.copyTo(r);
          this.reduce(r);
          return r;
        }
        revert(x) {
          return x;
        }
        reduce(x) {
          x.drShiftTo(this.m.t - 1, this.r2);
          if (x.t > this.m.t + 1) {
            x.t = this.m.t + 1;
            x.clamp();
          }
          this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
          this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
          while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
          x.subTo(this.r2, x);
          while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
        }
        mulTo(x, y, r) {
          x.multiplyTo(y, r);
          this.reduce(r);
        }
        sqrTo(x, r) {
          x.squareTo(r);
          this.reduce(r);
        }
      };
      NullExp = class {
        convert(x) {
          return x;
        }
        revert(x) {
          return x;
        }
        reduce(_x) {
        }
        mulTo(x, y, r) {
          x.multiplyTo(y, r);
        }
        sqrTo(x, r) {
          x.squareTo(r);
        }
      };
      lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
      lplim = (1 << 26) / lowprimes[lowprimes.length - 1];
      BigInteger.ZERO = nbv(0);
      BigInteger.ONE = nbv(1);
      ZERO_BI = 0n;
      ONE_BI = 1n;
      TWO_BI = 2n;
      SMALL_PRIMES = [
        2,
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
        101,
        103,
        107,
        109,
        113,
        127,
        131,
        137,
        139,
        149,
        151,
        157,
        163,
        167,
        173,
        179,
        181,
        191,
        193,
        197,
        199,
        211,
        223,
        227,
        229,
        233,
        239,
        241,
        251,
        257,
        263,
        269,
        271,
        277,
        281,
        283,
        293,
        307,
        311,
        313,
        317,
        331,
        337,
        347,
        349,
        353,
        359,
        367,
        373,
        379,
        383,
        389,
        397,
        401,
        409,
        419,
        421,
        431,
        433,
        439,
        443,
        449,
        457,
        461,
        463,
        467,
        479,
        487,
        491,
        499,
        503,
        509,
        521,
        523,
        541,
        547,
        557,
        563,
        569,
        571,
        577,
        587,
        593,
        599,
        601,
        607,
        613,
        617,
        619,
        631,
        641,
        643,
        647,
        653,
        659,
        661,
        673,
        677,
        683,
        691,
        701,
        709,
        719,
        727,
        733,
        739,
        743,
        751,
        757,
        761,
        769,
        773,
        787,
        797,
        809,
        811,
        821,
        823,
        827,
        829,
        839,
        853,
        857,
        859,
        863,
        877,
        881,
        883,
        887,
        907,
        911,
        919,
        929,
        937,
        941,
        947,
        953,
        967,
        971,
        977,
        983,
        991,
        997
      ];
      SMALL_PRIMES_BI = SMALL_PRIMES.map((p) => BigInt(p));
      BigInteger2 = class _BigInteger2 {
        static ONE = new _BigInteger2(1);
        static ZERO = new _BigInteger2(0);
        _v;
        constructor(a, b, unsigned) {
          if (a == null) {
            this._v = ZERO_BI;
          } else if (typeof a === "bigint") {
            this._v = a;
          } else if (typeof a === "number") {
            if (b === 1) {
              this._v = generateProbablePrime(a);
            } else {
              this._v = BigInt(a);
            }
          } else if (typeof a === "string") {
            this._v = parseFromString(a, b ?? 10);
          } else if (a instanceof Uint8Array) {
            this._v = bytesToBigInt(a, unsigned ?? true);
          } else {
            throw new Error(`BigInteger: unsupported input type ${typeof a}`);
          }
        }
        signum() {
          return this._v === ZERO_BI ? 0 : this._v > ZERO_BI ? 1 : -1;
        }
        compareTo(o) {
          if (this._v === o._v) return 0;
          return this._v > o._v ? 1 : -1;
        }
        bitLength() {
          return bitLengthOf(this._v);
        }
        testBit(n) {
          return (this._v >> BigInt(n) & ONE_BI) === ONE_BI;
        }
        isEven() {
          return (this._v & ONE_BI) === ZERO_BI;
        }
        /** @internal */
        negate() {
          return new _BigInteger2(-this._v);
        }
        abs() {
          return new _BigInteger2(this._v < ZERO_BI ? -this._v : this._v);
        }
        add(o) {
          return new _BigInteger2(this._v + o._v);
        }
        subtract(o) {
          return new _BigInteger2(this._v - o._v);
        }
        multiply(o) {
          return new _BigInteger2(this._v * o._v);
        }
        square() {
          return new _BigInteger2(this._v * this._v);
        }
        /** @internal */
        divide(o) {
          return new _BigInteger2(this._v / o._v);
        }
        /** Returns [quotient, remainder]. Matches jsbn divideAndRemainder. */
        divideAndRemainder(o) {
          return [new _BigInteger2(this._v / o._v), new _BigInteger2(this._v % o._v)];
        }
        /** Always non-negative result for positive modulus (Java/jsbn semantics). */
        mod(o) {
          const m = o._v;
          if (m === ZERO_BI) throw new Error("BigInteger.mod: divide by zero");
          let r = this._v % m;
          const absM = m < ZERO_BI ? -m : m;
          if (r < ZERO_BI) r += absM;
          return new _BigInteger2(r);
        }
        modPow(e, m) {
          return new _BigInteger2(modPowBI(this._v, e._v, m._v));
        }
        modPowInt(e, m) {
          return new _BigInteger2(modPowBI(this._v, BigInt(e), m._v));
        }
        modInverse(m) {
          return new _BigInteger2(modInverseBI(this._v, m._v));
        }
        gcd(o) {
          return new _BigInteger2(gcdBI(this._v, o._v));
        }
        shiftLeft(n) {
          return new _BigInteger2(n >= 0 ? this._v << BigInt(n) : this._v >> BigInt(-n));
        }
        shiftRight(n) {
          return new _BigInteger2(n >= 0 ? this._v >> BigInt(n) : this._v << BigInt(-n));
        }
        isProbablePrime(rounds) {
          return probablePrime(this._v, rounds);
        }
        toString(radix) {
          return this._v.toString(radix ?? 10);
        }
        /** Unsigned big-endian bytes; pads/truncates to `length` if given (jsbn parity). */
        toBuffer(length) {
          if (this._v < ZERO_BI) {
            return null;
          }
          return bigIntToBytes(this._v, length);
        }
      };
      BigInteger3 = BigInteger;
      _currentImpl = "jsbn";
      HASHES = {
        md5: (d) => md5(d),
        ripemd160: (d) => ripemd160(d),
        sha1: (d) => sha1(d),
        sha224: (d) => sha224(d),
        sha256: (d) => sha256(d),
        sha384: (d) => sha384(d),
        sha512: (d) => sha512(d)
      };
      webBackend = {
        name: "web",
        randomBytes(n) {
          const out = new Uint8Array(n);
          let off = 0;
          const c = getWebCrypto();
          while (off < n) {
            const chunk = Math.min(n - off, 65536);
            c.getRandomValues(out.subarray(off, off + chunk));
            off += chunk;
          }
          return out;
        },
        digest(alg, data) {
          if (alg === "md4") {
            throw new Error("MD4 is not supported in the browser backend (Node-only)");
          }
          const fn = HASHES[alg];
          if (!fn) throw new Error(`Unsupported hash algorithm: ${alg}`);
          return fn(data);
        },
        supportsHash(alg) {
          return alg !== "md4" && alg in HASHES;
        }
      };
      HEX_CHARS = "0123456789abcdef";
      utf8Encoder = new TextEncoder();
      utf8Decoder = new TextDecoder("utf-8", { fatal: false });
      componentsFormat = {
        privateExport(key, _options = {}) {
          if (!key.n || !key.d || !key.p || !key.q || !key.dmp1 || !key.dmq1 || !key.coeff) {
            throw new Error("components export: incomplete private key");
          }
          return {
            n: key.n.toBuffer(),
            e: key.e,
            d: key.d.toBuffer(),
            p: key.p.toBuffer(),
            q: key.q.toBuffer(),
            dmp1: key.dmp1.toBuffer(),
            dmq1: key.dmq1.toBuffer(),
            coeff: key.coeff.toBuffer()
          };
        },
        privateImport(key, data, _options = {}) {
          const d = data;
          if (!d.n || !d.e || !d.d || !d.p || !d.q || !d.dmp1 || !d.dmq1 || !d.coeff) {
            throw new Error("Invalid key data");
          }
          key.setPrivate(d.n, d.e, d.d, d.p, d.q, d.dmp1, d.dmq1, d.coeff);
        },
        publicExport(key, _options = {}) {
          if (!key.n) throw new Error("components export: missing modulus");
          return { n: key.n.toBuffer(), e: key.e };
        },
        publicImport(key, data, _options = {}) {
          const d = data;
          if (!d.n || d.e == null) throw new Error("Invalid key data");
          key.setPublic(d.n, d.e);
        },
        autoImport(key, data) {
          if (typeof data !== "object" || data === null) return false;
          const d = data;
          if (!d.n || d.e == null) return false;
          if (d.d && d.p && d.q && d.dmp1 && d.dmq1 && d.coeff) {
            componentsFormat.privateImport?.(key, data);
            return true;
          }
          componentsFormat.publicImport?.(key, data);
          return true;
        }
      };
      PRIVATE_OPENING = "-----BEGIN OPENSSH PRIVATE KEY-----";
      PRIVATE_CLOSING = "-----END OPENSSH PRIVATE KEY-----";
      opensshFormat = {
        /** OpenSSH private-key export. The two checkint placeholders are left as zero (no integrity field is written). */
        privateExport(key, options = {}) {
          if (!key.n || !key.d || !key.p || !key.q || !key.coeff) {
            throw new Error("OpenSSH export: incomplete private key");
          }
          const nbuf = key.n.toBuffer();
          let ebuf = new Uint8Array(4);
          writeUInt32BE(key.e, ebuf, 0);
          while (ebuf.length > 0 && ebuf[0] === 0) ebuf = ebuf.subarray(1);
          const dbuf = key.d.toBuffer();
          const coeffbuf = key.coeff.toBuffer();
          const pbuf = key.p.toBuffer();
          const qbuf = key.q.toBuffer();
          const commentbuf = key.sshcomment ? fromUtf8(key.sshcomment) : new Uint8Array(0);
          const pubkeyLength = 11 + // length-prefixed 'ssh-rsa' (4-byte uint32 length + 7 chars)
          4 + ebuf.byteLength + // 4 = length prefix for e
          4 + nbuf.byteLength;
          const privateKeyLength = 8 + // two uint32 checkints (file-corruption / wrong-passphrase detector)
          11 + // length-prefixed 'ssh-rsa' (4 + 7)
          4 + nbuf.byteLength + // 4 = length prefix for n
          4 + ebuf.byteLength + // 4 = length prefix for e
          4 + dbuf.byteLength + // 4 = length prefix for d
          4 + coeffbuf.byteLength + // 4 = length prefix for iqmp (coeff)
          4 + pbuf.byteLength + // 4 = length prefix for p
          4 + qbuf.byteLength + // 4 = length prefix for q
          4 + commentbuf.byteLength;
          const paddingLength = Math.ceil(privateKeyLength / 8) * 8 - privateKeyLength;
          const totalLength = 15 + // 'openssh-key-v1\0' magic
          16 + // two length-prefixed 'none' strings (cipher + kdf), 2*(4+4)
          4 + // empty kdfoptions (length prefix only, zero bytes of payload)
          4 + // numkeys (uint32 = 1)
          4 + // pubkey-blob length prefix
          pubkeyLength + 4 + // private-section length prefix
          privateKeyLength + paddingLength;
          const buf = new Uint8Array(totalLength);
          const writer = new SshWriter(buf);
          buf.set(fromUtf8("openssh-key-v1"), 0);
          buf[14] = 0;
          writer.off = 15;
          writer.writeString(fromUtf8("none"));
          writer.writeString(fromUtf8("none"));
          writer.writeString(new Uint8Array(0));
          writer.writeUInt32(1);
          writer.writeUInt32(pubkeyLength);
          writer.writeString(fromUtf8("ssh-rsa"));
          writer.writeString(ebuf);
          writer.writeString(nbuf);
          writer.writeUInt32(privateKeyLength + paddingLength);
          writer.off += 8;
          writer.writeString(fromUtf8("ssh-rsa"));
          writer.writeString(nbuf);
          writer.writeString(ebuf);
          writer.writeString(dbuf);
          writer.writeString(coeffbuf);
          writer.writeString(pbuf);
          writer.writeString(qbuf);
          writer.writeString(commentbuf);
          let pad = 1;
          while (writer.off < totalLength) {
            buf[writer.off++] = pad++;
          }
          if (options.type === "der") return buf;
          return `${PRIVATE_OPENING}
${linebrk(toBase64(buf), 70)}
${PRIVATE_CLOSING}
`;
        },
        /** OpenSSH private-key import. The format omits CRT exponents, so `dp` and `dq` are derived from `d mod (p−1)` and `d mod (q−1)`. */
        privateImport(key, data, options = {}) {
          let buffer;
          if (options.type !== "der") {
            const text = data instanceof Uint8Array ? toUtf8(data) : data;
            const trimmed = trimSurroundingText(text, PRIVATE_OPENING, PRIVATE_CLOSING).replace(
              /\s+/g,
              ""
            );
            buffer = fromBase64(trimmed);
          } else if (data instanceof Uint8Array) {
            buffer = data;
          } else {
            throw new Error("Unsupported key format");
          }
          const magic = toUtf8(buffer.subarray(0, 14));
          if (magic !== "openssh-key-v1") throw new Error("Invalid file format.");
          const reader = new SshReader(buffer);
          reader.off = 15;
          if (toUtf8(reader.readString()) !== "none") throw new Error("Unsupported key type");
          if (toUtf8(reader.readString()) !== "none") throw new Error("Unsupported key type");
          if (toUtf8(reader.readString()) !== "") throw new Error("Unsupported key type");
          reader.off += 4;
          reader.off += 4;
          if (toUtf8(reader.readString()) !== "ssh-rsa") throw new Error("Unsupported key type");
          reader.readString();
          reader.readString();
          reader.off += 4;
          const checkInt1 = readUInt32BE(reader.buf, reader.off);
          reader.off += 4;
          const checkInt2 = readUInt32BE(reader.buf, reader.off);
          reader.off += 4;
          if (checkInt1 !== checkInt2) {
            throw new Error(
              "OpenSSH private key: checksum mismatch (file may be corrupted or encrypted)"
            );
          }
          if (toUtf8(reader.readString()) !== "ssh-rsa") throw new Error("Unsupported key type");
          const n = reader.readString();
          const e = reader.readString();
          const d = reader.readString();
          const coeff = reader.readString();
          const p = reader.readString();
          const q = reader.readString();
          const dint = new BigInteger3(d);
          const pint = new BigInteger3(p);
          const qint = new BigInteger3(q);
          const dp = dint.mod(pint.subtract(BigInteger3.ONE)).toBuffer();
          const dq = dint.mod(qint.subtract(BigInteger3.ONE)).toBuffer();
          key.setPrivate(n, e, d, p, q, dp, dq, coeff);
          key.sshcomment = toUtf8(reader.readString());
        },
        publicExport(key, options = {}) {
          if (!key.n) throw new Error("OpenSSH export: missing modulus");
          let ebuf = new Uint8Array(4);
          writeUInt32BE(key.e, ebuf, 0);
          while (ebuf.length > 0 && ebuf[0] === 0) ebuf = ebuf.subarray(1);
          const nbuf = key.n.toBuffer();
          const buf = new Uint8Array(ebuf.byteLength + 4 + nbuf.byteLength + 4 + "ssh-rsa".length + 4);
          const writer = new SshWriter(buf);
          writer.writeString(fromUtf8("ssh-rsa"));
          writer.writeString(ebuf);
          writer.writeString(nbuf);
          if (options.type === "der") return buf;
          const comment = key.sshcomment ?? "";
          return `ssh-rsa ${toBase64(buf)} ${comment}
`;
        },
        publicImport(key, data, options = {}) {
          let buffer;
          if (options.type !== "der") {
            const text = data instanceof Uint8Array ? toUtf8(data) : data;
            if (text.substring(0, 8) !== "ssh-rsa ") throw new Error("Unsupported key format");
            let pemEnd = text.indexOf(" ", 8);
            if (pemEnd === -1) {
              pemEnd = text.length;
            } else {
              key.sshcomment = text.substring(pemEnd + 1).replace(/\s+|\n\r|\n|\r$/gm, "");
            }
            const pem = text.substring(8, pemEnd).replace(/\s+/g, "");
            buffer = fromBase64(pem);
          } else if (data instanceof Uint8Array) {
            buffer = data;
          } else {
            throw new Error("Unsupported key format");
          }
          const reader = new SshReader(buffer);
          const type = toUtf8(reader.readString());
          if (type !== "ssh-rsa") throw new Error(`Invalid key type: ${type}`);
          const e = reader.readString();
          const n = reader.readString();
          key.setPublic(n, e);
        },
        autoImport(key, data) {
          const text = typeof data === "string" ? data : data instanceof Uint8Array ? new TextDecoder().decode(data) : null;
          if (text === null) return false;
          if (/^[\S\s]*-----BEGIN OPENSSH PRIVATE KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END OPENSSH PRIVATE KEY-----[\S\s]*$/g.test(
            text
          )) {
            opensshFormat.privateImport?.(key, text);
            return true;
          }
          if (/^[\S\s]*ssh-rsa \s*(?=(([A-Za-z0-9+/=]+\s*)+))\1[\S\s]*$/g.test(text)) {
            opensshFormat.publicImport?.(key, text);
            return true;
          }
          return false;
        }
      };
      SshReader = class {
        constructor(buf) {
          this.buf = buf;
        }
        buf;
        off = 0;
        readString() {
          const len = readUInt32BE(this.buf, this.off);
          if (this.off + 4 + len > this.buf.length) {
            throw new Error(
              `OpenSSH: string length ${len} exceeds buffer (offset=${this.off}, buffer=${this.buf.length})`
            );
          }
          this.off += 4;
          const out = this.buf.subarray(this.off, this.off + len);
          this.off += len;
          return out;
        }
      };
      SshWriter = class {
        constructor(buf) {
          this.buf = buf;
        }
        buf;
        off = 0;
        writeString(data) {
          writeUInt32BE(data.byteLength, this.buf, this.off);
          this.off += 4;
          this.buf.set(data, this.off);
          this.off += data.byteLength;
        }
        writeUInt32(value) {
          writeUInt32BE(value, this.buf, this.off);
          this.off += 4;
        }
      };
      OID = {
        /** rsaEncryption — used in PKCS#8 AlgorithmIdentifier */
        RSA_ENCRYPTION: "1.2.840.113549.1.1.1"
      };
      Tag = {
        INTEGER: 2,
        BIT_STRING: 3,
        OCTET_STRING: 4,
        NULL: 5,
        OBJECT_IDENTIFIER: 6,
        SEQUENCE: 48
      };
      DerReader = class _DerReader {
        pos = 0;
        bytes;
        constructor(bytes) {
          this.bytes = bytes;
        }
        get position() {
          return this.pos;
        }
        get remaining() {
          return this.bytes.length - this.pos;
        }
        hasMore() {
          return this.pos < this.bytes.length;
        }
        /**
         * Read a generic TLV. If `expectedTag` is supplied, asserts the tag matches.
         * Returns the value bytes (no tag, no length octets).
         */
        readTlv(expectedTag) {
          if (this.pos >= this.bytes.length) {
            throw new Error("DerReader: unexpected end of input");
          }
          const tag = this.bytes[this.pos++];
          if (expectedTag !== void 0 && tag !== expectedTag) {
            throw new Error(
              `DerReader: expected ${tagName(expectedTag)} (0x${expectedTag.toString(16)}) but got ${tagName(tag)} (0x${tag.toString(16)})`
            );
          }
          const length = this.readLength();
          const end = this.pos + length;
          if (end > this.bytes.length) {
            throw new Error(
              `DerReader: TLV length ${length} exceeds buffer (pos=${this.pos}, len=${this.bytes.length})`
            );
          }
          const value = this.bytes.subarray(this.pos, end);
          this.pos = end;
          return { tag, value };
        }
        readLength() {
          if (this.pos >= this.bytes.length) {
            throw new Error("DerReader: missing length octet");
          }
          const first = this.bytes[this.pos++];
          if ((first & 128) === 0) return first;
          const numBytes = first & 127;
          if (numBytes === 0) {
            throw new Error("DerReader: indefinite length not permitted in DER");
          }
          if (numBytes > 4) {
            throw new Error(`DerReader: unsupported length width ${numBytes}`);
          }
          let len = 0;
          for (let i = 0; i < numBytes; i++) {
            if (this.pos >= this.bytes.length) {
              throw new Error("DerReader: truncated length");
            }
            const b = this.bytes[this.pos++];
            if (i === 0 && b === 0 && numBytes > 1) {
              throw new Error("DerReader: non-canonical length (leading zero in long-form)");
            }
            len = len << 8 | b;
          }
          if (len < 128) {
            throw new Error(`DerReader: non-canonical length (long-form used for length ${len} < 128)`);
          }
          return len;
        }
        /** Read a SEQUENCE and return a sub-reader scoped to its contents. */
        readSequence() {
          return new _DerReader(this.readTlv(Tag.SEQUENCE).value);
        }
        /** Read an INTEGER and return its raw value bytes (DER content). */
        readInteger() {
          const bytes = this.readTlv(Tag.INTEGER).value;
          if (bytes.length === 0) {
            throw new Error("DerReader: INTEGER must have at least one content octet");
          }
          if (bytes.length >= 2) {
            const b0 = bytes[0];
            const b1 = bytes[1];
            if (b1 !== void 0) {
              if (b0 === 0 && (b1 & 128) === 0) {
                throw new Error("DerReader: non-canonical INTEGER (redundant leading 0x00)");
              }
              if (b0 === 255 && (b1 & 128) !== 0) {
                throw new Error("DerReader: non-canonical INTEGER (redundant leading 0xff)");
              }
            }
          }
          return bytes;
        }
        /**
         * Read an INTEGER, decoding it as an unsigned JavaScript number.
         * Throws if the value doesn't fit in a safe-integer.
         */
        readSmallInteger() {
          const bytes = this.readInteger();
          let i = 0;
          while (i < bytes.length - 1 && bytes[i] === 0) i++;
          const meaningful = bytes.subarray(i);
          if (meaningful.length > 6) {
            throw new Error(`DerReader: integer too large for safe number (${meaningful.length} bytes)`);
          }
          let n = 0;
          for (const b of meaningful) {
            n = n * 256 + b;
          }
          return n;
        }
        /** Read an OBJECT IDENTIFIER and return its dotted-string form. */
        readOid() {
          return decodeOid(this.readTlv(Tag.OBJECT_IDENTIFIER).value);
        }
        /** Read a NULL TLV. Throws if the value is non-empty. */
        readNull() {
          const { value } = this.readTlv(Tag.NULL);
          if (value.length !== 0) {
            throw new Error(`DerReader: NULL must be zero-length, got ${value.length}`);
          }
        }
        /** Read a BIT STRING and return its value bytes INCLUDING the leading unused-bits octet. */
        readBitStringRaw() {
          return this.readTlv(Tag.BIT_STRING).value;
        }
        /**
         * Read a BIT STRING and return its content octets (after the unused-bits byte).
         * Asserts unused-bits is zero.
         */
        readBitString() {
          const raw = this.readBitStringRaw();
          if (raw.length === 0) {
            throw new Error("DerReader: empty BIT STRING");
          }
          if (raw[0] !== 0) {
            throw new Error(`DerReader: non-zero unused bits (${raw[0]}) not supported`);
          }
          return raw.subarray(1);
        }
        /** Read an OCTET STRING and return its value bytes. */
        readOctetString() {
          return this.readTlv(Tag.OCTET_STRING).value;
        }
      };
      DerWriter = class {
        chunks = [];
        sequenceStack = [];
        /** Write a generic TLV with the given tag and value bytes. */
        writeTlv(tag, value) {
          this.chunks.push(new Uint8Array([tag]));
          this.chunks.push(encodeLength(value.length));
          this.chunks.push(value);
        }
        /**
         * Write an INTEGER. Accepts:
         *  - a positive JS number,
         *  - an unsigned big-endian byte array (a leading zero will be prepended
         *    if the MSB is set, to preserve positive sign).
         */
        writeInteger(value) {
          if (typeof value === "number") {
            this.writeTlv(Tag.INTEGER, encodeSmallInteger(value));
          } else {
            this.writeTlv(Tag.INTEGER, normalizePositiveInteger(value));
          }
        }
        writeOid(oid) {
          this.writeTlv(Tag.OBJECT_IDENTIFIER, encodeOid(oid));
        }
        writeNull() {
          this.writeTlv(Tag.NULL, new Uint8Array(0));
        }
        /** Write a BIT STRING. Always emits an unused-bits prefix byte of 0x00. */
        writeBitString(content) {
          const body = new Uint8Array(content.length + 1);
          body[0] = 0;
          body.set(content, 1);
          this.writeTlv(Tag.BIT_STRING, body);
        }
        /**
         * Write a BIT STRING whose value bytes (including the leading unused-bits
         * octet) are supplied directly. Mirrors callers that build the bit-string
         * payload externally.
         */
        writeBitStringRaw(valueIncludingUnusedBitsByte) {
          this.writeTlv(Tag.BIT_STRING, valueIncludingUnusedBitsByte);
        }
        writeOctetString(content) {
          this.writeTlv(Tag.OCTET_STRING, content);
        }
        /** Begin a nested SEQUENCE; subsequent writes go into it until endSequence(). */
        startSequence() {
          this.sequenceStack.push(this.chunks);
          this.chunks = [];
        }
        /** Close the most recently opened SEQUENCE, emitting it as a TLV in the parent. */
        endSequence() {
          if (this.sequenceStack.length === 0) {
            throw new Error("DerWriter: endSequence without startSequence");
          }
          const inner = concat(...this.chunks);
          this.chunks = this.sequenceStack.pop();
          this.writeTlv(Tag.SEQUENCE, inner);
        }
        /** Return the assembled DER bytes. Throws if any SEQUENCE is unclosed. */
        toBytes() {
          if (this.sequenceStack.length > 0) {
            throw new Error(`DerWriter: ${this.sequenceStack.length} SEQUENCE(s) unclosed`);
          }
          return concat(...this.chunks);
        }
      };
      PRIVATE_OPENING2 = "-----BEGIN RSA PRIVATE KEY-----";
      PRIVATE_CLOSING2 = "-----END RSA PRIVATE KEY-----";
      PUBLIC_OPENING = "-----BEGIN RSA PUBLIC KEY-----";
      PUBLIC_CLOSING = "-----END RSA PUBLIC KEY-----";
      pkcs1Format = {
        privateExport(key, options = {}) {
          if (!key.n || !key.d || !key.p || !key.q || !key.dmp1 || !key.dmq1 || !key.coeff) {
            throw new Error("PKCS#1 export: incomplete private key");
          }
          const w = new DerWriter();
          w.startSequence();
          w.writeInteger(0);
          w.writeInteger(key.n.toBuffer());
          w.writeInteger(key.e);
          w.writeInteger(key.d.toBuffer());
          w.writeInteger(key.p.toBuffer());
          w.writeInteger(key.q.toBuffer());
          w.writeInteger(key.dmp1.toBuffer());
          w.writeInteger(key.dmq1.toBuffer());
          w.writeInteger(key.coeff.toBuffer());
          w.endSequence();
          const bytes = w.toBytes();
          return options.type === "der" ? bytes : encodePem(bytes, PRIVATE_OPENING2, PRIVATE_CLOSING2);
        },
        privateImport(key, data, options = {}) {
          const buffer = resolveBytes(data, options, PRIVATE_OPENING2, PRIVATE_CLOSING2);
          const seq = new DerReader(buffer).readSequence();
          seq.readSmallInteger();
          const n = seq.readInteger();
          const e = seq.readSmallInteger();
          const d = seq.readInteger();
          const p = seq.readInteger();
          const q = seq.readInteger();
          const dmp1 = seq.readInteger();
          const dmq1 = seq.readInteger();
          const coeff = seq.readInteger();
          key.setPrivate(n, e, d, p, q, dmp1, dmq1, coeff);
        },
        publicExport(key, options = {}) {
          if (!key.n) throw new Error("PKCS#1 export: missing modulus");
          const w = new DerWriter();
          w.startSequence();
          w.writeInteger(key.n.toBuffer());
          w.writeInteger(key.e);
          w.endSequence();
          const bytes = w.toBytes();
          return options.type === "der" ? bytes : encodePem(bytes, PUBLIC_OPENING, PUBLIC_CLOSING);
        },
        publicImport(key, data, options = {}) {
          const buffer = resolveBytes(data, options, PUBLIC_OPENING, PUBLIC_CLOSING);
          const seq = new DerReader(buffer).readSequence();
          const n = seq.readInteger();
          const e = seq.readSmallInteger();
          key.setPublic(n, e);
        },
        autoImport(key, data) {
          const text = typeof data === "string" ? data : data instanceof Uint8Array ? new TextDecoder().decode(data) : null;
          if (text === null) return false;
          if (/^[\S\s]*-----BEGIN RSA PRIVATE KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END RSA PRIVATE KEY-----[\S\s]*$/g.test(
            text
          )) {
            pkcs1Format.privateImport?.(key, text);
            return true;
          }
          if (/^[\S\s]*-----BEGIN RSA PUBLIC KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END RSA PUBLIC KEY-----[\S\s]*$/g.test(
            text
          )) {
            pkcs1Format.publicImport?.(key, text);
            return true;
          }
          return false;
        }
      };
      PRIVATE_OPENING3 = "-----BEGIN PRIVATE KEY-----";
      PRIVATE_CLOSING3 = "-----END PRIVATE KEY-----";
      PUBLIC_OPENING2 = "-----BEGIN PUBLIC KEY-----";
      PUBLIC_CLOSING2 = "-----END PUBLIC KEY-----";
      pkcs8Format = {
        privateExport(key, options = {}) {
          if (!key.n || !key.d || !key.p || !key.q || !key.dmp1 || !key.dmq1 || !key.coeff) {
            throw new Error("PKCS#8 export: incomplete private key");
          }
          const body = new DerWriter();
          body.startSequence();
          body.writeInteger(0);
          body.writeInteger(key.n.toBuffer());
          body.writeInteger(key.e);
          body.writeInteger(key.d.toBuffer());
          body.writeInteger(key.p.toBuffer());
          body.writeInteger(key.q.toBuffer());
          body.writeInteger(key.dmp1.toBuffer());
          body.writeInteger(key.dmq1.toBuffer());
          body.writeInteger(key.coeff.toBuffer());
          body.endSequence();
          const w = new DerWriter();
          w.startSequence();
          w.writeInteger(0);
          w.startSequence();
          w.writeOid(OID.RSA_ENCRYPTION);
          w.writeNull();
          w.endSequence();
          w.writeOctetString(body.toBytes());
          w.endSequence();
          const bytes = w.toBytes();
          return options.type === "der" ? bytes : encodePem(bytes, PRIVATE_OPENING3, PRIVATE_CLOSING3);
        },
        privateImport(key, data, options = {}) {
          const buffer = resolveBytes(data, options, PRIVATE_OPENING3, PRIVATE_CLOSING3);
          const outer = new DerReader(buffer).readSequence();
          const outerVersion = outer.readSmallInteger();
          if (outerVersion !== 0 && outerVersion !== 1) {
            throw new Error(`PKCS#8: unsupported version ${outerVersion} (RFC 5958 \xA72 requires 0 or 1)`);
          }
          const header = outer.readSequence();
          const oid = header.readOid();
          if (oid !== OID.RSA_ENCRYPTION) {
            throw pkcs8OidError(oid, "private");
          }
          header.readNull();
          const body = new DerReader(outer.readOctetString()).readSequence();
          const innerVersion = body.readSmallInteger();
          if (innerVersion !== 0) {
            throw new Error(
              `PKCS#8: PKCS#1 multi-prime keys (version ${innerVersion}) are not supported`
            );
          }
          const n = body.readInteger();
          const e = body.readSmallInteger();
          const d = body.readInteger();
          const p = body.readInteger();
          const q = body.readInteger();
          const dmp1 = body.readInteger();
          const dmq1 = body.readInteger();
          const coeff = body.readInteger();
          key.setPrivate(n, e, d, p, q, dmp1, dmq1, coeff);
        },
        publicExport(key, options = {}) {
          if (!key.n) throw new Error("PKCS#8 export: missing modulus");
          const inner = new DerWriter();
          inner.startSequence();
          inner.writeInteger(key.n.toBuffer());
          inner.writeInteger(key.e);
          inner.endSequence();
          const w = new DerWriter();
          w.startSequence();
          w.startSequence();
          w.writeOid(OID.RSA_ENCRYPTION);
          w.writeNull();
          w.endSequence();
          w.writeBitString(inner.toBytes());
          w.endSequence();
          const bytes = w.toBytes();
          return options.type === "der" ? bytes : encodePem(bytes, PUBLIC_OPENING2, PUBLIC_CLOSING2);
        },
        publicImport(key, data, options = {}) {
          const buffer = resolveBytes(data, options, PUBLIC_OPENING2, PUBLIC_CLOSING2);
          const outer = new DerReader(buffer).readSequence();
          const header = outer.readSequence();
          const oid = header.readOid();
          if (oid !== OID.RSA_ENCRYPTION) {
            throw pkcs8OidError(oid, "public");
          }
          header.readNull();
          const inner = new DerReader(outer.readBitString()).readSequence();
          const n = inner.readInteger();
          const e = inner.readSmallInteger();
          key.setPublic(n, e);
        },
        autoImport(key, data) {
          const text = typeof data === "string" ? data : data instanceof Uint8Array ? new TextDecoder().decode(data) : null;
          if (text === null) return false;
          if (/^[\S\s]*-----BEGIN PRIVATE KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END PRIVATE KEY-----[\S\s]*$/g.test(
            text
          )) {
            pkcs8Format.privateImport?.(key, text);
            return true;
          }
          if (/^[\S\s]*-----BEGIN PUBLIC KEY-----\s*(?=(([A-Za-z0-9+/=]+\s*)+))\1-----END PUBLIC KEY-----[\S\s]*$/g.test(
            text
          )) {
            pkcs8Format.publicImport?.(key, text);
            return true;
          }
          return false;
        }
      };
      FORMATS = {
        pkcs1: pkcs1Format,
        pkcs8: pkcs8Format,
        components: componentsFormat,
        openssh: opensshFormat
      };
      DIGEST_LENGTH = Object.freeze({
        md4: 16,
        md5: 16,
        ripemd160: 20,
        sha1: 20,
        sha224: 28,
        sha256: 32,
        sha384: 48,
        sha512: 64
      });
      DEFAULT_HASH = "sha1";
      OaepScheme = class {
        constructor(key, options) {
          this.key = key;
          this.options = options;
        }
        key;
        options;
        hash() {
          return this.options.encryptionSchemeOptions.hash ?? DEFAULT_HASH;
        }
        mgf() {
          const userMgf = this.options.encryptionSchemeOptions.mgf;
          if (userMgf) return userMgf;
          const backend = this.options.backend;
          return (seed, maskLength, hash) => mgf1(seed, maskLength, hash, backend);
        }
        maxMessageLength() {
          return this.key.encryptedDataLength - 2 * DIGEST_LENGTH[this.hash()] - 2;
        }
        encPad(buffer) {
          const hash = this.hash();
          const mgf = this.mgf();
          const label = this.options.encryptionSchemeOptions.label ?? new Uint8Array(0);
          const emLen = this.key.encryptedDataLength;
          const hLen = DIGEST_LENGTH[hash];
          if (buffer.length > emLen - 2 * hLen - 2) {
            throw new Error(
              `Message is too long to encode into an encoded message with a length of ${emLen} bytes, increaseemLen to fix this error (minimum size: ${emLen - 2 * hLen - 2})`
            );
          }
          const lHash = this.options.backend.digest(hash, label);
          const PS = new Uint8Array(emLen - buffer.length - 2 * hLen - 1);
          PS[PS.length - 1] = 1;
          const DB2 = concat(lHash, PS, buffer);
          const seed = this.options.backend.randomBytes(hLen);
          const dbMask = mgf(seed, DB2.length, hash);
          for (let i = 0; i < DB2.length; i++) DB2[i] = DB2[i] ^ dbMask[i];
          const seedMask = mgf(DB2, hLen, hash);
          for (let i = 0; i < seed.length; i++) seed[i] = seed[i] ^ seedMask[i];
          const em = new Uint8Array(1 + seed.length + DB2.length);
          em[0] = 0;
          em.set(seed, 1);
          em.set(DB2, 1 + seed.length);
          return em;
        }
        /**
         * Constant-time OAEP decode per RFC 8017 §7.1.2: all failure modes —
         * wrong Y byte, lHash mismatch, no 0x01 separator, message length over
         * the geometric maximum — must be indistinguishable in timing or a
         * Manger oracle recovers plaintext in ~10⁵ queries. We accumulate a
         * single `bad` flag without branches and return null once at the end.
         */
        encUnPad(buffer) {
          const hash = this.hash();
          const mgf = this.mgf();
          const label = this.options.encryptionSchemeOptions.label ?? new Uint8Array(0);
          const hLen = DIGEST_LENGTH[hash];
          if (buffer.length < 2 * hLen + 2) return null;
          const work = buffer.slice();
          let bad = work[0] === 0 ? 0 : 1;
          const seed = work.subarray(1, hLen + 1);
          const DB2 = work.subarray(1 + hLen);
          const seedMask = mgf(DB2, hLen, hash);
          for (let i = 0; i < seed.length; i++) seed[i] = seed[i] ^ seedMask[i];
          const dbMask = mgf(seed, DB2.length, hash);
          for (let i = 0; i < DB2.length; i++) DB2[i] = DB2[i] ^ dbMask[i];
          const lHash = this.options.backend.digest(hash, label);
          const lHashEM = DB2.subarray(0, hLen);
          bad |= constantTimeEqual(lHashEM, lHash) ? 0 : 1;
          let found = 0;
          let msgStart = 0;
          for (let j = hLen; j < DB2.length; j++) {
            const b = DB2[j];
            const isOne = (b ^ 1) - 1 >>> 31 & 1;
            const isZero = ((b | -b) >>> 31 ^ 1) & 1;
            const notFoundYet = 1 - found & 1;
            const recordMask = -(notFoundYet & isOne);
            msgStart = msgStart & ~recordMask | j + 1 & recordMask;
            bad |= notFoundYet & 1 - isOne & 1 - isZero;
            found |= isOne;
          }
          bad |= 1 - found;
          if (bad) return null;
          const msg = DB2.subarray(msgStart).slice();
          if (msg.length > this.maxMessageLength()) return null;
          return msg;
        }
      };
      oaepScheme = {
        isEncryption: true,
        isSignature: false,
        makeScheme(key, options) {
          return new OaepScheme(key, options);
        }
      };
      RSA_NO_PADDING = 3;
      SIGN_INFO_HEAD = {
        md5: fromHex("3020300c06082a864886f70d020505000410"),
        sha1: fromHex("3021300906052b0e03021a05000414"),
        sha224: fromHex("302d300d06096086480165030402040500041c"),
        sha256: fromHex("3031300d060960864801650304020105000420"),
        sha384: fromHex("3041300d060960864801650304020205000430"),
        sha512: fromHex("3051300d060960864801650304020305000440"),
        ripemd160: fromHex("3021300906052b2403020105000414")
      };
      DEFAULT_HASH2 = "sha256";
      Pkcs1Scheme = class {
        constructor(key, options) {
          this.key = key;
          this.options = options;
        }
        key;
        options;
        noPadding() {
          return this.options.encryptionSchemeOptions.padding === RSA_NO_PADDING;
        }
        maxMessageLength() {
          if (this.noPadding()) return this.key.encryptedDataLength;
          return this.key.encryptedDataLength - 11;
        }
        encPad(buffer, opts) {
          const { type } = opts ?? {};
          if (buffer.length > this.maxMessageLength()) {
            throw new Error(
              `Message too long for RSA (n=${this.key.encryptedDataLength}, l=${buffer.length})`
            );
          }
          if (this.noPadding()) {
            const filled2 = new Uint8Array(this.maxMessageLength() - buffer.length);
            return concat(filled2, buffer);
          }
          if (type === 1) {
            const filled2 = new Uint8Array(this.key.encryptedDataLength - buffer.length - 1);
            filled2.fill(255, 0, filled2.length - 1);
            filled2[0] = 1;
            filled2[filled2.length - 1] = 0;
            return concat(filled2, buffer);
          }
          const filled = new Uint8Array(this.key.encryptedDataLength - buffer.length);
          filled[0] = 0;
          filled[1] = 2;
          const rand = this.options.backend.randomBytes(filled.length - 3);
          for (let i = 0; i < rand.length; i++) {
            let r = rand[i];
            while (r === 0) {
              r = this.options.backend.randomBytes(1)[0];
            }
            filled[i + 2] = r;
          }
          filled[filled.length - 1] = 0;
          return concat(filled, buffer);
        }
        /**
         * Constant-time PKCS#1 v1.5 decode per RFC 8017 §7.2.2: header byte,
         * padding-type byte, PS validity, and minimum PS length all accumulate
         * into a single bitwise `bad` flag with no early return; one `return
         * null` for all failure modes.
         *
         * Full Bleichenbacher mitigation (RFC §7.2.2 NOTE — return synthetic
         * plaintext instead of null) would require session-key plumbing and an
         * API change (callers expect a throw). This closes only the internal
         * differential timing oracle; the valid/invalid binary oracle inherent
         * to PKCS#1 v1.5 remains — use OAEP for untrusted ciphertexts.
         */
        encUnPad(buffer, opts) {
          const { type } = opts ?? {};
          if (this.noPadding()) {
            let lastZero = -1;
            for (let j = buffer.length - 1; j >= 0; j--) {
              if (buffer[j] === 0) {
                lastZero = j;
                break;
              }
            }
            return buffer.subarray(lastZero + 1).slice();
          }
          if (buffer.length < 11) return null;
          const expectedType = type === 1 ? 1 : 2;
          let bad = buffer[0];
          bad |= buffer[1] ^ expectedType;
          let found = 0;
          let sepPos = 0;
          for (let i = 2; i < buffer.length; i++) {
            const b = buffer[i];
            const isZero = ((b | -b) >>> 31 ^ 1) & 1;
            const notFoundYet = 1 - found & 1;
            if (expectedType === 1) {
              const isNotFF = ((b ^ 255) === 0 ? 0 : 1) & 1;
              bad |= notFoundYet & 1 - isZero & isNotFF;
            }
            const recordMask = -(notFoundYet & isZero);
            sepPos = sepPos & ~recordMask | i & recordMask;
            found |= isZero;
          }
          bad |= 1 - found;
          bad |= sepPos - 10 >>> 31 & 1;
          if (bad) return null;
          return buffer.subarray(sepPos + 1).slice();
        }
        sign(buffer) {
          const hashAlgorithm = this.options.signingSchemeOptions.hash ?? DEFAULT_HASH2;
          const hash = this.options.backend.digest(hashAlgorithm, buffer);
          const padded = this.pkcs1pad(hash, hashAlgorithm);
          const signed = this.key.$doPrivate(new this.key.BI(padded));
          const out = signed.toBuffer(this.key.encryptedDataLength);
          if (!out) throw new Error("PKCS#1 sign: output overflow");
          return out;
        }
        verify(buffer, signature) {
          if (this.noPadding()) return false;
          const hashAlgorithm = this.options.signingSchemeOptions.hash ?? DEFAULT_HASH2;
          const hash = this.options.backend.digest(hashAlgorithm, buffer);
          const padded = this.pkcs1pad(hash, hashAlgorithm);
          let m;
          try {
            m = this.key.$doPublic(new this.key.BI(signature)).toBuffer();
          } catch {
            return false;
          }
          if (!m) return false;
          return constantTimeEqual(m, padded);
        }
        pkcs1pad(hashBuf, hashAlgorithm) {
          const digest = SIGN_INFO_HEAD[hashAlgorithm];
          if (!digest) throw new Error(`Unsupported hash algorithm: ${hashAlgorithm}`);
          const data = concat(digest, hashBuf);
          if (data.length + 10 > this.key.encryptedDataLength) {
            throw new Error(`Key is too short for signing algorithm (${hashAlgorithm})`);
          }
          const filled = new Uint8Array(this.key.encryptedDataLength - data.length - 1);
          filled.fill(255, 0, filled.length - 1);
          filled[0] = 1;
          filled[filled.length - 1] = 0;
          return concat(filled, data);
        }
      };
      pkcs1Scheme = {
        isEncryption: true,
        isSignature: true,
        makeScheme(key, options) {
          return new Pkcs1Scheme(key, options);
        }
      };
      DEFAULT_HASH3 = "sha1";
      DEFAULT_SALT_LENGTH = 20;
      PssScheme = class {
        constructor(key, options) {
          this.key = key;
          this.options = options;
        }
        key;
        options;
        hash() {
          return this.options.signingSchemeOptions.hash ?? DEFAULT_HASH3;
        }
        mgf() {
          const userMgf = this.options.signingSchemeOptions.mgf;
          if (userMgf) return userMgf;
          const backend = this.options.backend;
          return (seed, maskLength, hash) => mgf1(seed, maskLength, hash, backend);
        }
        saltLen() {
          return this.options.signingSchemeOptions.saltLength ?? DEFAULT_SALT_LENGTH;
        }
        sign(buffer) {
          const hash = this.hash();
          const mHash = this.options.backend.digest(hash, buffer);
          const encoded = this.emsaPssEncode(mHash, this.key.keySize - 1);
          const signed = this.key.$doPrivate(new this.key.BI(encoded));
          const out = signed.toBuffer(this.key.encryptedDataLength);
          if (!out) throw new Error("PSS sign: output overflow");
          return out;
        }
        verify(buffer, signature) {
          const hash = this.hash();
          const emLen = Math.ceil((this.key.keySize - 1) / 8);
          let m;
          try {
            m = this.key.$doPublic(new this.key.BI(signature)).toBuffer(emLen);
          } catch {
            return false;
          }
          if (!m) return false;
          const mHash = this.options.backend.digest(hash, buffer);
          return this.emsaPssVerify(mHash, m, this.key.keySize - 1);
        }
        /** EMSA-PSS-ENCODE — RFC 3447 §9.1.1 */
        emsaPssEncode(mHash, emBits) {
          const hash = this.hash();
          const mgf = this.mgf();
          const sLen = this.saltLen();
          const hLen = DIGEST_LENGTH[hash];
          const emLen = Math.ceil(emBits / 8);
          if (emLen < hLen + sLen + 2) {
            throw new Error(
              `Output length passed to emBits(${emBits}) is too small for the options specified(${hash}, ${sLen}). To fix this issue increase the value of emBits. (minimum size: ${8 * hLen + 8 * sLen + 9})`
            );
          }
          const salt = this.options.backend.randomBytes(sLen);
          const mPrime = new Uint8Array(8 + hLen + sLen);
          mPrime.set(mHash, 8);
          mPrime.set(salt, 8 + mHash.length);
          const H = this.options.backend.digest(hash, mPrime);
          const DB2 = new Uint8Array(emLen - hLen - 1);
          DB2[emLen - hLen - 1 - sLen - 1] = 1;
          DB2.set(salt, emLen - hLen - 1 - sLen);
          const dbMask = mgf(H, DB2.length, hash);
          for (let i = 0; i < DB2.length; i++) DB2[i] = DB2[i] ^ dbMask[i];
          const bits = 8 * emLen - emBits;
          const mask = 255 ^ 255 >> 8 - bits << 8 - bits & 255;
          DB2[0] = DB2[0] & mask;
          const EM = new Uint8Array(emLen);
          EM.set(DB2, 0);
          EM.set(H, DB2.length);
          EM[EM.length - 1] = 188;
          return EM;
        }
        /**
         * EMSA-PSS-VERIFY per RFC 8017 §9.1.2. All input-dependent checks
         * (trailer byte, leftmost-bits zero, PS-zeros, separator 0x01, H == H')
         * accumulate into a single `bad` flag with one `return bad === 0` at the
         * end. PSS verify operates on public data, so this is hygiene rather
         * than a tight side-channel requirement — but RFC step 11 mandates
         * evaluating all checks before deciding.
         */
        emsaPssVerify(mHash, EM, emBits) {
          const hash = this.hash();
          const mgf = this.mgf();
          const sLen = this.saltLen();
          const hLen = DIGEST_LENGTH[hash];
          const emLen = Math.ceil(emBits / 8);
          if (emLen < hLen + sLen + 2) return false;
          if (EM.length !== emLen) return false;
          let bad = 0;
          bad |= EM[EM.length - 1] ^ 188;
          const DB2 = EM.slice(0, emLen - hLen - 1);
          const bits = 8 * emLen - emBits;
          let topMask = 0;
          for (let i = 0; i < bits; i++) topMask |= 1 << 7 - i;
          bad |= DB2[0] & topMask;
          const H = EM.subarray(emLen - hLen - 1, emLen - 1);
          const dbMask = mgf(H, DB2.length, hash);
          for (let i = 0; i < DB2.length; i++) DB2[i] = DB2[i] ^ dbMask[i];
          const adjustedMask = 255 ^ 255 >> 8 - bits << 8 - bits & 255;
          DB2[0] = DB2[0] & adjustedMask;
          const sepIdx = emLen - hLen - sLen - 2;
          for (let i = 0; i < DB2.length; i++) {
            const b = DB2[i];
            if (i < sepIdx) {
              bad |= b;
            } else if (i === sepIdx) {
              bad |= b ^ 1;
            }
          }
          const salt = DB2.subarray(DB2.length - sLen);
          const mPrime = new Uint8Array(8 + hLen + sLen);
          mPrime.set(mHash, 8);
          mPrime.set(salt, 8 + mHash.length);
          const HPrime = this.options.backend.digest(hash, mPrime);
          bad |= constantTimeEqual(H, HPrime) ? 0 : 1;
          return bad === 0;
        }
      };
      pssScheme = {
        isEncryption: false,
        isSignature: true,
        makeScheme(key, options) {
          return new PssScheme(key, options);
        }
      };
      SCHEMES = {
        pkcs1: pkcs1Scheme,
        pkcs1_oaep: oaepScheme,
        pss: pssScheme
      };
      NODE_HASHES = [
        "md4",
        "md5",
        "ripemd160",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512"
      ];
      SUPPORTED_HASH_ALGORITHMS = {
        node: NODE_HASHES,
        node10: NODE_HASHES,
        iojs: NODE_HASHES,
        browser: ["md5", "ripemd160", "sha1", "sha256", "sha512"]
      };
      DEFAULT_ENCRYPTION_SCHEME = "pkcs1_oaep";
      DEFAULT_SIGNING_SCHEME = "pss";
      EXPORT_FORMAT_ALIASES = {
        private: "pkcs1-private-pem",
        "private-der": "pkcs1-private-der",
        public: "pkcs8-public-pem",
        "public-der": "pkcs8-public-der"
      };
      warnedEnvironment = false;
      JsEngine = class {
        constructor(key) {
          this.key = key;
          this.pkcs1 = pkcs1Scheme.makeScheme(key, key.options);
        }
        key;
        /** Always a PKCS#1 v1.5 scheme — used for usePrivate / usePublic paths. */
        pkcs1;
        encrypt(buffer, usePrivate = false) {
          const max = this.key.maxMessageLength;
          if (max <= 0) throw new Error("Engine: key not initialised");
          const buffersCount = Math.ceil(buffer.length / max) || 1;
          const dividedSize = Math.ceil(buffer.length / buffersCount) || 1;
          const chunks = [];
          if (buffersCount === 1) {
            chunks.push(buffer);
          } else {
            for (let i = 0; i < buffersCount; i++) {
              chunks.push(buffer.subarray(i * dividedSize, (i + 1) * dividedSize));
            }
          }
          const out = [];
          for (const chunk of chunks) {
            const padded = usePrivate ? this.pkcs1.encPad(chunk, { type: 1 }) : this.key.encryptionScheme.encPad(chunk);
            const bi = new this.key.BI(padded);
            const result = usePrivate ? this.key.$doPrivate(bi) : this.key.$doPublic(bi);
            const bytes = result.toBuffer(this.key.encryptedDataLength);
            if (!bytes) throw new Error("Engine: RSA primitive returned oversize integer");
            out.push(bytes);
          }
          return concat(...out);
        }
        decrypt(buffer, usePublic = false) {
          const chunkLen = this.key.encryptedDataLength;
          if (buffer.length % chunkLen !== 0) {
            throw new Error("Incorrect data or key");
          }
          const count = buffer.length / chunkLen;
          const parts = [];
          let bad = 0;
          for (let i = 0; i < count; i++) {
            const off = i * chunkLen;
            const ct = buffer.subarray(off, off + chunkLen);
            const bi = new this.key.BI(ct);
            const result = usePublic ? this.key.$doPublic(bi) : this.key.$doPrivate(bi);
            const padded = result.toBuffer(chunkLen);
            if (!padded) throw new Error("Engine: RSA primitive returned oversize integer");
            const unpadded = usePublic ? this.pkcs1.encUnPad(padded, { type: 1 }) : this.key.encryptionScheme.encUnPad(padded);
            parts.push(unpadded ?? padded.subarray(0, 0));
            bad |= unpadded ? 0 : 1;
          }
          if (bad) throw new Error("Decryption failed");
          return concat(...parts);
        }
      };
      warnedSmallKey = false;
      RSAKey = class {
        n = null;
        e = 0;
        d = null;
        p = null;
        q = null;
        dmp1 = null;
        dmq1 = null;
        coeff = null;
        // Cached per-update key metrics.
        cache = {
          keyBitLength: 0,
          keyByteLength: 0
        };
        // Scheme bindings — populated by setOptions().
        encryptionScheme;
        signingScheme;
        options;
        /** OpenSSH key comment field (preserved across import/export). */
        sshcomment;
        /**
         * BigInteger constructor that owns this key's components. Read off
         * `n.constructor` so a later `setBigIntegerImpl()` swap by another
         * NodeRSA instance can't corrupt operations on this key — fresh
         * BigIntegers spawned during sign/encrypt/blinding stay the same class
         * as `n`, `d`, `p`, `q` etc.
         */
        get BI() {
          if (!this.n) throw new Error("RSAKey: no key components");
          return this.n.constructor;
        }
        /**
         * Bind encryption + signing scheme instances to this key. If both schemes
         * resolve to the same provider (PKCS#1 v1.5 covers both), one instance is
         * shared so internal padding state stays consistent. Throws on unknown
         * scheme names.
         */
        setOptions(options, schemes) {
          this.options = options;
          const sigProvider = schemes[options.signingScheme];
          const encProvider = schemes[options.encryptionScheme];
          if (!sigProvider) throw new Error(`Unknown signing scheme: ${options.signingScheme}`);
          if (!encProvider) throw new Error(`Unknown encryption scheme: ${options.encryptionScheme}`);
          if (sigProvider === encProvider) {
            const scheme = sigProvider.makeScheme(this, options);
            this.signingScheme = scheme;
            this.encryptionScheme = scheme;
          } else {
            this.encryptionScheme = encProvider.makeScheme(this, options);
            this.signingScheme = sigProvider.makeScheme(this, options);
          }
        }
        /**
         * Generate a fresh `B`-bit private key with public exponent E (hex string).
         * Matches v1's algorithm and RNG call pattern exactly.
         */
        generate(B, E) {
          if (B < 512) {
            throw new Error(
              `Key size ${B} bits is cryptographically broken (< 512); refusing to generate`
            );
          }
          if (B < 2048 && !warnedSmallKey) {
            warnedSmallKey = true;
            console.warn(
              `node-rsa: generating ${B}-bit RSA key \u2014 below NIST SP 800-56B \xA76.1.6.2 minimum (2048 bits); not recommended for production`
            );
          }
          const qs = B >> 1;
          this.e = Number.parseInt(E, 16);
          const ee = new BigInteger3(E, 16);
          const mrRounds = B >= 4096 ? 16 : B >= 3072 ? 28 : 40;
          const minPQDiff = BigInteger3.ONE.shiftLeft((B >> 1) - 100);
          while (true) {
            while (true) {
              this.p = new BigInteger3(B - qs, 1);
              if (this.p.subtract(BigInteger3.ONE).gcd(ee).compareTo(BigInteger3.ONE) === 0 && this.p.isProbablePrime(mrRounds)) {
                break;
              }
            }
            while (true) {
              this.q = new BigInteger3(qs, 1);
              if (this.q.subtract(BigInteger3.ONE).gcd(ee).compareTo(BigInteger3.ONE) === 0 && this.q.isProbablePrime(mrRounds)) {
                break;
              }
            }
            if (this.p.compareTo(this.q) <= 0) {
              const t = this.p;
              this.p = this.q;
              this.q = t;
            }
            if (this.p.subtract(this.q).compareTo(minPQDiff) < 0) continue;
            const p1 = this.p.subtract(BigInteger3.ONE);
            const q1 = this.q.subtract(BigInteger3.ONE);
            const phi = p1.multiply(q1);
            if (phi.gcd(ee).compareTo(BigInteger3.ONE) === 0) {
              this.n = this.p.multiply(this.q);
              if (this.n.bitLength() < B) continue;
              this.d = ee.modInverse(phi);
              this.dmp1 = this.d.mod(p1);
              this.dmq1 = this.d.mod(q1);
              this.coeff = this.q.modInverse(this.p);
              break;
            }
          }
          this.recalculateCache();
        }
        /**
         * Install private-key components (raw big-endian bytes; E may be a number).
         * If any CRT field (P/Q/DP/DQ/C) is omitted the key works without CRT —
         * slower decrypt but valid. Throws if N/E/D are missing or if CRT fields
         * are present but mathematically inconsistent (Boneh-DeMillo-Lipton
         * fault-attack guard).
         */
        setPrivate(N, E, D, P, Q, DP, DQ, C) {
          if (!N || N.length === 0) throw new Error("Invalid RSA private key");
          if (typeof E !== "number" && (!E || E.length === 0)) throw new Error("Invalid RSA private key");
          if (!D || D.length === 0) throw new Error("Invalid RSA private key");
          this.n = new BigInteger3(N);
          this.e = typeof E === "number" ? E : readBigEndianUInt(E);
          this.d = new BigInteger3(D);
          if (P && Q && DP && DQ && C) {
            this.p = new BigInteger3(P);
            this.q = new BigInteger3(Q);
            this.dmp1 = new BigInteger3(DP);
            this.dmq1 = new BigInteger3(DQ);
            this.coeff = new BigInteger3(C);
          }
          this.validateExponent();
          this.validatePrivateConsistency();
          this.recalculateCache();
        }
        /** Install public-key components (raw big-endian bytes; E may be a number). Throws if N/E are missing or E is invalid. */
        setPublic(N, E) {
          if (!N || N.length === 0) throw new Error("Invalid RSA public key");
          if (typeof E !== "number" && (!E || E.length === 0)) throw new Error("Invalid RSA public key");
          this.n = new BigInteger3(N);
          this.e = typeof E === "number" ? E : readBigEndianUInt(E);
          this.validateExponent();
          this.recalculateCache();
        }
        /**
         * RFC 8017 §3.1 requires 1 < e < n with e odd. e=1 makes ciphertext ==
         * plaintext; even e breaks RSA invertibility entirely. The e < n side
         * is implicit (n ≥ 2^512 ≫ any JS-number-encodable e).
         */
        validateExponent() {
          if (this.e <= 1) {
            throw new Error("Invalid RSA exponent: e must be > 1");
          }
          if ((this.e & 1) === 0) {
            throw new Error("Invalid RSA exponent: e must be odd");
          }
        }
        /**
         * Cross-check CRT invariants for an imported private key. Inconsistent
         * components (n ≠ p·q, mismatched dp/dq, bad coeff) don't just produce
         * garbage on decrypt — they enable Boneh-DeMillo-Lipton fault attacks
         * where a single faulted signature reveals gcd(s_correct − s_faulted, n)
         * and factors n. Skipped when CRT components are absent (basic n, e, d
         * key still works, just without CRT).
         */
        validatePrivateConsistency() {
          if (!this.n || !this.d || !this.p || !this.q || !this.dmp1 || !this.dmq1 || !this.coeff) {
            return;
          }
          if (this.p.multiply(this.q).compareTo(this.n) !== 0) {
            throw new Error("RSA private key inconsistent: n \u2260 p \xD7 q");
          }
          const p1 = this.p.subtract(BigInteger3.ONE);
          const q1 = this.q.subtract(BigInteger3.ONE);
          if (this.d.mod(p1).compareTo(this.dmp1) !== 0) {
            throw new Error("RSA private key inconsistent: dp \u2260 d mod (p \u2212 1)");
          }
          if (this.d.mod(q1).compareTo(this.dmq1) !== 0) {
            throw new Error("RSA private key inconsistent: dq \u2260 d mod (q \u2212 1)");
          }
          if (this.q.multiply(this.coeff).mod(this.p).compareTo(BigInteger3.ONE) !== 0) {
            throw new Error("RSA private key inconsistent: q \xD7 coeff \u2262 1 (mod p)");
          }
          const eBig = new BigInteger3(this.e.toString(16), 16);
          if (eBig.multiply(this.dmp1).mod(p1).compareTo(BigInteger3.ONE) !== 0) {
            throw new Error("RSA private key inconsistent: e \xD7 dp \u2262 1 (mod p \u2212 1)");
          }
          if (eBig.multiply(this.dmq1).mod(q1).compareTo(BigInteger3.ONE) !== 0) {
            throw new Error("RSA private key inconsistent: e \xD7 dq \u2262 1 (mod q \u2212 1)");
          }
        }
        /** x^d mod n, using CRT if p/q are available, otherwise direct. */
        $doPrivate(x) {
          if (!this.n || !this.d) throw new Error("No private key");
          if (x.signum() < 0 || x.compareTo(this.n) >= 0) {
            throw new Error("RSA: input out of range (must be 0 \u2264 x < n)");
          }
          const blinding = this.makeBlinding();
          const inputX = blinding ? x.multiply(blinding.re).mod(this.n) : x;
          let result;
          if (!this.p || !this.q || !this.dmp1 || !this.dmq1 || !this.coeff) {
            result = inputX.modPow(this.d, this.n);
          } else {
            const xp = inputX.mod(this.p).modPow(this.dmp1, this.p);
            const xq = inputX.mod(this.q).modPow(this.dmq1, this.q);
            result = xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
          }
          if (blinding) {
            result = result.multiply(blinding.rInv).mod(this.n);
          }
          return result;
        }
        /**
         * Produce a fresh blinding pair (r^e mod n, r^-1 mod n) for one private
         * operation. Returns null only in the astronomically rare case that the
         * RNG keeps producing r with gcd(r, n) ≠ 1 — probability ≈ 2/√n per
         * attempt; 10 attempts is overkill safety.
         *
         * Returns null also if there's no backend yet (e.g., key without
         * setOptions() — only happens in some test setups).
         */
        makeBlinding() {
          if (!this.n || !this.options) return null;
          const n = this.n;
          const BI = this.BI;
          const byteLen = (n.bitLength() + 7 >> 3) + 1;
          const two = new BI(Uint8Array.of(2));
          const nMinus3 = n.subtract(BI.ONE).subtract(two);
          for (let attempt = 0; attempt < 10; attempt++) {
            const rb = this.options.backend.randomBytes(byteLen);
            const r = new BI(rb).mod(nMinus3).add(two);
            const rInv = r.modInverse(n);
            if (rInv.signum() === 0) continue;
            const re = r.modPowInt(this.e, n);
            return { re, rInv };
          }
          return null;
        }
        /** x^e mod n. */
        $doPublic(x) {
          if (!this.n) throw new Error("No public key");
          if (x.signum() < 0 || x.compareTo(this.n) >= 0) {
            throw new Error("RSA: input out of range (must be 0 \u2264 x < n)");
          }
          return x.modPowInt(this.e, this.n);
        }
        /** True iff `d` is loaded (n, e implied). */
        isPrivate() {
          return !!(this.n && this.e && this.d);
        }
        /** True iff `n` and `e` are set. With `strict=true` additionally requires `d` to be absent. */
        isPublic(strict) {
          if (!this.n || !this.e) return false;
          if (strict && this.d) return false;
          return true;
        }
        /** Modulus size in bits (0 if no key loaded). */
        get keySize() {
          return this.cache.keyBitLength;
        }
        /** Ciphertext block size in bytes. */
        get encryptedDataLength() {
          return this.cache.keyByteLength;
        }
        /** Largest single-chunk plaintext the configured encryption scheme will accept. */
        get maxMessageLength() {
          return this.encryptionScheme.maxMessageLength();
        }
        /** Recompute cached key-size metrics. */
        recalculateCache() {
          if (!this.n) {
            this.cache = { keyBitLength: 0, keyByteLength: 0 };
            return;
          }
          const keyBitLength = this.n.bitLength();
          this.cache = {
            keyBitLength,
            keyByteLength: keyBitLength + 6 >> 3
          };
        }
        /**
         * Clear all key material from this instance. Call when the key is no
         * longer needed to reduce the window in which private components are
         * reachable from the JS heap (heap snapshots, core dumps, swap).
         *
         * JavaScript has no guaranteed deterministic memory zeroing — GC-managed
         * BigInteger internals may linger until collected. This method removes
         * references as early as possible, which is the strongest guarantee the
         * language offers.
         */
        destroy() {
          this.n = null;
          this.e = 0;
          this.d = null;
          this.p = null;
          this.q = null;
          this.dmp1 = null;
          this.dmq1 = null;
          this.coeff = null;
          this.cache = { keyBitLength: 0, keyByteLength: 0 };
        }
        /** Convenience: get the backend bound via setOptions. */
        get backend() {
          return this.options.backend;
        }
      };
      NodeRSA = class {
        $options;
        keyPair;
        engine = null;
        $cache = {};
        constructor(key, format, options) {
          let opts;
          let fmt;
          if (typeof format === "object" && format !== null) {
            opts = format;
            fmt = void 0;
          } else {
            fmt = format;
            opts = options;
          }
          const env = getInternal().environment;
          this.$options = makeDefaultOptions(env);
          this.keyPair = new RSAKey();
          if (opts) {
            applyOptions(this.$options, opts);
            this.rewireScheme();
          }
          if (key instanceof Uint8Array || typeof key === "string") {
            this.importKey(key, fmt);
          } else if (key && typeof key === "object") {
            const gen = key;
            this.generateKeyPair(gen.b, gen.e);
          }
          if (!opts && !key) this.rewireScheme();
        }
        setOptions(options) {
          if (options.bigIntImpl && options.bigIntImpl !== this.$options.bigIntImpl && this.keyPair.n != null) {
            throw new Error(
              "NodeRSA: bigIntImpl can only be set on a fresh instance (before importKey / generateKeyPair). Pass it in the constructor options, or set it before importing."
            );
          }
          applyOptions(this.$options, options);
          this.rewireScheme();
          return this;
        }
        generateKeyPair(bits = 2048, exp = 65537) {
          if (bits % 8 !== 0) throw new Error("Key size must be a multiple of 8.");
          const cfg = getInternal();
          const expHex = exp.toString(16);
          if (cfg.keygenFor && this.$options.environment !== "browser") {
            cfg.keygenFor(this.keyPair, bits, expHex);
          } else {
            this.keyPair.generate(bits, expHex);
          }
          this.$cache = {};
          this.rewireScheme();
          return this;
        }
        importKey(keyData, format) {
          if (keyData == null || typeof keyData === "string" && keyData.length === 0) {
            throw new Error("Empty key given");
          }
          const resolvedFormat = format ? EXPORT_FORMAT_ALIASES[format] ?? format : format;
          const imported = detectAndImport(this.keyPair, keyData, resolvedFormat);
          if (!imported && resolvedFormat === void 0) {
            throw new Error("Key format must be specified");
          }
          this.$cache = {};
          this.rewireScheme();
          return this;
        }
        exportKey(format = "private") {
          const resolved = EXPORT_FORMAT_ALIASES[format] ?? format;
          if (!this.$cache[resolved]) {
            const exported = detectAndExport(this.keyPair, resolved);
            if (exported === void 0) throw new Error("Export failed");
            this.$cache[resolved] = exported;
          }
          return this.$cache[resolved];
        }
        isPrivate() {
          return this.keyPair.isPrivate();
        }
        isPublic(strict) {
          return this.keyPair.isPublic(strict);
        }
        isEmpty() {
          return !(this.keyPair.n || this.keyPair.e || this.keyPair.d);
        }
        getKeySize() {
          return this.keyPair.keySize;
        }
        getMaxMessageSize() {
          return this.keyPair.maxMessageLength;
        }
        encrypt(buffer, encoding, sourceEncoding) {
          return this.$$encryptKey(false, buffer, encoding, sourceEncoding);
        }
        decrypt(buffer, encoding) {
          return this.$$decryptKey(false, buffer, encoding);
        }
        encryptPrivate(buffer, encoding, sourceEncoding) {
          return this.$$encryptKey(true, buffer, encoding, sourceEncoding);
        }
        decryptPublic(buffer, encoding) {
          return this.$$decryptKey(true, buffer, encoding);
        }
        sign(buffer, encoding, sourceEncoding) {
          if (!this.isPrivate()) throw new Error("This is not private key");
          const data = this.$getDataForEncrypt(buffer, sourceEncoding);
          const res = this.keyPair.signingScheme.sign(data);
          return encoding && encoding !== "buffer" ? encodeBytes(res, encoding) : res;
        }
        verify(buffer, signature, sourceEncoding, signatureEncoding) {
          if (!this.isPublic()) throw new Error("This is not public key");
          const data = this.$getDataForEncrypt(buffer, sourceEncoding);
          const sig = typeof signature === "string" ? decodeBytes(signature, signatureEncoding) : signature;
          return this.keyPair.signingScheme.verify(data, sig);
        }
        // internals
        $$encryptKey(usePrivate, buffer, encoding, sourceEncoding) {
          try {
            const data = this.$getDataForEncrypt(buffer, sourceEncoding);
            const res = this.ensureEngine().encrypt(data, usePrivate);
            return encoding && encoding !== "buffer" ? encodeBytes(res, encoding) : res;
          } catch {
            throw new Error("Error during encryption");
          }
        }
        $$decryptKey(usePublic, buffer, encoding) {
          try {
            const bytes = typeof buffer === "string" ? fromBase64(buffer) : buffer;
            const res = this.ensureEngine().decrypt(bytes, usePublic);
            return this.$getDecryptedData(res, encoding);
          } catch {
            throw new Error("Error during decryption");
          }
        }
        $getDataForEncrypt(buffer, encoding) {
          if (typeof buffer === "string") {
            return encoding && encoding !== "utf8" ? decodeBytes(buffer, encoding) : fromUtf8(buffer);
          }
          if (typeof buffer === "number") return fromUtf8(String(buffer));
          if (buffer instanceof Uint8Array) return buffer;
          if (buffer !== null && typeof buffer === "object") return fromUtf8(JSON.stringify(buffer));
          throw new Error("Unexpected data type");
        }
        $getDecryptedData(bytes, encoding) {
          const enc = encoding ?? "buffer";
          if (enc === "buffer") return bytes;
          if (enc === "json") return JSON.parse(toUtf8(bytes));
          return encodeBytes(bytes, enc);
        }
        rewireScheme() {
          const cfg = getInternal();
          const opts = {
            signingScheme: this.$options.signingScheme,
            encryptionScheme: this.$options.encryptionScheme,
            signingSchemeOptions: this.$options.signingSchemeOptions,
            encryptionSchemeOptions: this.$options.encryptionSchemeOptions,
            environment: this.$options.environment,
            backend: cfg.backend
          };
          const forcedJs = this.$options.environment === "browser";
          const schemes = forcedJs ? SCHEMES : cfg.schemes ?? SCHEMES;
          this.keyPair.setOptions(opts, schemes);
          this.engine = null;
        }
        ensureEngine() {
          if (this.engine) return this.engine;
          const cfg = getInternal();
          const forcedJs = this.$options.environment === "browser";
          if (!forcedJs && cfg.engineFor) {
            this.engine = cfg.engineFor(this.keyPair, this.$options);
          } else {
            this.engine = new JsEngine(this.keyPair);
          }
          return this.engine;
        }
      };
      setBigIntegerImpl("native");
      bootstrap({
        environment: "browser",
        backend: webBackend
        // Browser bundle ships only the pure-JS engine — there is no node:crypto.
      });
      index_browser_default = NodeRSA;
    }
  });

  // src/security.rsa.js
  var require_security_rsa = __commonJS({
    "src/security.rsa.js"(exports, module) {
      var NodeRSA2 = (init_index_browser(), __toCommonJS(index_browser_exports)).default;
      var rsa = {
        INVALID_CALL_WITHOUT_KEYSIZE: "generateKeys called without keySize argument",
        INVALID_CALL_WITH_INVALID_KEYSIZE: "Key size must be a number and a multiple of 8.",
        // both parameters must be strings, publicKey PEM formatted
        encrypt: async function(publicKey, message) {
          const keyObj = await globalThis.crypto.subtle.importKey(
            "spki",
            pemToDer(publicKey),
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
          );
          const msgBytes = new TextEncoder().encode(message);
          const encrypted = await globalThis.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            keyObj,
            msgBytes
          );
          return btoa(String.fromCodePoint(...new Uint8Array(encrypted)));
        },
        // both parameters must be strings, privateKey PEM formatted
        decrypt: async function(privateKey, message) {
          const keyObj = await globalThis.crypto.subtle.importKey(
            "pkcs8",
            pemToDer(privateKey),
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
          );
          const msgBytes = Uint8Array.from(atob(message), (c) => c.codePointAt(0));
          const decrypted = await globalThis.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            keyObj,
            msgBytes
          );
          return new TextDecoder().decode(decrypted);
        },
        // generate PEM formatted public / private key pair asynchronously
        generateKeys: function(keySize, next) {
          return new Promise((resolve, reject) => {
            try {
              if (!keySize) {
                throw new Error(rsa.INVALID_CALL_WITHOUT_KEYSIZE);
              }
              keySize = Number(keySize);
              if (Number.isNaN(keySize) || keySize % 8 !== 0) {
                throw new Error(rsa.INVALID_CALL_WITH_INVALID_KEYSIZE);
              }
              const startTime = Date.now();
              let key = new NodeRSA2({ b: keySize });
              const endTime = Date.now();
              const keys = {
                keySize,
                time: endTime - startTime,
                private: key.exportKey("pkcs8-private-pem"),
                public: key.exportKey("pkcs8-public-pem")
              };
              if (next) {
                next(null, keys);
              }
              return resolve(keys);
            } catch (error) {
              if (next) {
                next(error);
              }
              return reject(error);
            }
          });
        },
        sign: function(privateKey, message) {
          let key = new NodeRSA2(privateKey);
          return key.sign(message, "base64");
        },
        verify: function(publicKey, message, signature) {
          let key = new NodeRSA2(publicKey);
          return key.verify(message, signature, "utf8", "base64");
        }
      };
      function pemToDer(pem) {
        const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.codePointAt(i);
        return bytes.buffer;
      }
      module.exports = rsa;
    }
  });

  // (disabled):crypto
  var require_crypto = __commonJS({
    "(disabled):crypto"() {
    }
  });

  // (disabled):buffer
  var require_buffer = __commonJS({
    "(disabled):buffer"() {
    }
  });

  // node_modules/js-sha256/src/sha256.js
  var require_sha256 = __commonJS({
    "node_modules/js-sha256/src/sha256.js"(exports, module) {
      (function() {
        "use strict";
        var ERROR = "input is invalid type";
        var WINDOW = typeof window === "object";
        var root = WINDOW ? window : {};
        if (root.JS_SHA256_NO_WINDOW) {
          WINDOW = false;
        }
        var WEB_WORKER = !WINDOW && typeof self === "object";
        var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === "object" && process.versions && process.versions.node;
        if (NODE_JS) {
          root = global;
        } else if (WEB_WORKER) {
          root = self;
        }
        var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === "object" && module.exports;
        var AMD = typeof define === "function" && define.amd;
        var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== "undefined";
        var HEX_CHARS2 = "0123456789abcdef".split("");
        var EXTRA = [-2147483648, 8388608, 32768, 128];
        var SHIFT = [24, 16, 8, 0];
        var K2 = [
          1116352408,
          1899447441,
          3049323471,
          3921009573,
          961987163,
          1508970993,
          2453635748,
          2870763221,
          3624381080,
          310598401,
          607225278,
          1426881987,
          1925078388,
          2162078206,
          2614888103,
          3248222580,
          3835390401,
          4022224774,
          264347078,
          604807628,
          770255983,
          1249150122,
          1555081692,
          1996064986,
          2554220882,
          2821834349,
          2952996808,
          3210313671,
          3336571891,
          3584528711,
          113926993,
          338241895,
          666307205,
          773529912,
          1294757372,
          1396182291,
          1695183700,
          1986661051,
          2177026350,
          2456956037,
          2730485921,
          2820302411,
          3259730800,
          3345764771,
          3516065817,
          3600352804,
          4094571909,
          275423344,
          430227734,
          506948616,
          659060556,
          883997877,
          958139571,
          1322822218,
          1537002063,
          1747873779,
          1955562222,
          2024104815,
          2227730452,
          2361852424,
          2428436474,
          2756734187,
          3204031479,
          3329325298
        ];
        var OUTPUT_TYPES = ["hex", "array", "digest", "arrayBuffer"];
        var blocks = [];
        if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
          Array.isArray = function(obj) {
            return Object.prototype.toString.call(obj) === "[object Array]";
          };
        }
        if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
          ArrayBuffer.isView = function(obj) {
            return typeof obj === "object" && obj.buffer && obj.buffer.constructor === ArrayBuffer;
          };
        }
        var createOutputMethod = function(outputType, is224) {
          return function(message) {
            return new Sha256(is224, true).update(message)[outputType]();
          };
        };
        var createMethod = function(is224) {
          var method = createOutputMethod("hex", is224);
          if (NODE_JS) {
            method = nodeWrap(method, is224);
          }
          method.create = function() {
            return new Sha256(is224);
          };
          method.update = function(message) {
            return method.create().update(message);
          };
          for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
            var type = OUTPUT_TYPES[i];
            method[type] = createOutputMethod(type, is224);
          }
          return method;
        };
        var nodeWrap = function(method, is224) {
          var crypto = require_crypto();
          var Buffer2 = require_buffer().Buffer;
          var algorithm = is224 ? "sha224" : "sha256";
          var bufferFrom;
          if (Buffer2.from && !root.JS_SHA256_NO_BUFFER_FROM) {
            bufferFrom = Buffer2.from;
          } else {
            bufferFrom = function(message) {
              return new Buffer2(message);
            };
          }
          var nodeMethod = function(message) {
            if (typeof message === "string") {
              return crypto.createHash(algorithm).update(message, "utf8").digest("hex");
            } else {
              if (message === null || message === void 0) {
                throw new Error(ERROR);
              } else if (message.constructor === ArrayBuffer) {
                message = new Uint8Array(message);
              }
            }
            if (Array.isArray(message) || ArrayBuffer.isView(message) || message.constructor === Buffer2) {
              return crypto.createHash(algorithm).update(bufferFrom(message)).digest("hex");
            } else {
              return method(message);
            }
          };
          return nodeMethod;
        };
        var createHmacOutputMethod = function(outputType, is224) {
          return function(key, message) {
            return new HmacSha256(key, is224, true).update(message)[outputType]();
          };
        };
        var createHmacMethod = function(is224) {
          var method = createHmacOutputMethod("hex", is224);
          method.create = function(key) {
            return new HmacSha256(key, is224);
          };
          method.update = function(key, message) {
            return method.create(key).update(message);
          };
          for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
            var type = OUTPUT_TYPES[i];
            method[type] = createHmacOutputMethod(type, is224);
          }
          return method;
        };
        function Sha256(is224, sharedMemory) {
          if (sharedMemory) {
            blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
            this.blocks = blocks;
          } else {
            this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
          }
          if (is224) {
            this.h0 = 3238371032;
            this.h1 = 914150663;
            this.h2 = 812702999;
            this.h3 = 4144912697;
            this.h4 = 4290775857;
            this.h5 = 1750603025;
            this.h6 = 1694076839;
            this.h7 = 3204075428;
          } else {
            this.h0 = 1779033703;
            this.h1 = 3144134277;
            this.h2 = 1013904242;
            this.h3 = 2773480762;
            this.h4 = 1359893119;
            this.h5 = 2600822924;
            this.h6 = 528734635;
            this.h7 = 1541459225;
          }
          this.block = this.start = this.bytes = this.hBytes = 0;
          this.finalized = this.hashed = false;
          this.first = true;
          this.is224 = is224;
        }
        Sha256.prototype.update = function(message) {
          if (this.finalized) {
            return;
          }
          var notString, type = typeof message;
          if (type !== "string") {
            if (type === "object") {
              if (message === null) {
                throw new Error(ERROR);
              } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
                message = new Uint8Array(message);
              } else if (!Array.isArray(message)) {
                if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
                  throw new Error(ERROR);
                }
              }
            } else {
              throw new Error(ERROR);
            }
            notString = true;
          }
          var code, index = 0, i, length = message.length, blocks2 = this.blocks;
          while (index < length) {
            if (this.hashed) {
              this.hashed = false;
              blocks2[0] = this.block;
              blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
            }
            if (notString) {
              for (i = this.start; index < length && i < 64; ++index) {
                blocks2[i >> 2] |= message[index] << SHIFT[i++ & 3];
              }
            } else {
              for (i = this.start; index < length && i < 64; ++index) {
                code = message.charCodeAt(index);
                if (code < 128) {
                  blocks2[i >> 2] |= code << SHIFT[i++ & 3];
                } else if (code < 2048) {
                  blocks2[i >> 2] |= (192 | code >> 6) << SHIFT[i++ & 3];
                  blocks2[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3];
                } else if (code < 55296 || code >= 57344) {
                  blocks2[i >> 2] |= (224 | code >> 12) << SHIFT[i++ & 3];
                  blocks2[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[i++ & 3];
                  blocks2[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3];
                } else {
                  code = 65536 + ((code & 1023) << 10 | message.charCodeAt(++index) & 1023);
                  blocks2[i >> 2] |= (240 | code >> 18) << SHIFT[i++ & 3];
                  blocks2[i >> 2] |= (128 | code >> 12 & 63) << SHIFT[i++ & 3];
                  blocks2[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[i++ & 3];
                  blocks2[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3];
                }
              }
            }
            this.lastByteIndex = i;
            this.bytes += i - this.start;
            if (i >= 64) {
              this.block = blocks2[16];
              this.start = i - 64;
              this.hash();
              this.hashed = true;
            } else {
              this.start = i;
            }
          }
          if (this.bytes > 4294967295) {
            this.hBytes += this.bytes / 4294967296 << 0;
            this.bytes = this.bytes % 4294967296;
          }
          return this;
        };
        Sha256.prototype.finalize = function() {
          if (this.finalized) {
            return;
          }
          this.finalized = true;
          var blocks2 = this.blocks, i = this.lastByteIndex;
          blocks2[16] = this.block;
          blocks2[i >> 2] |= EXTRA[i & 3];
          this.block = blocks2[16];
          if (i >= 56) {
            if (!this.hashed) {
              this.hash();
            }
            blocks2[0] = this.block;
            blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
          }
          blocks2[14] = this.hBytes << 3 | this.bytes >>> 29;
          blocks2[15] = this.bytes << 3;
          this.hash();
        };
        Sha256.prototype.hash = function() {
          var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6, h = this.h7, blocks2 = this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;
          for (j = 16; j < 64; ++j) {
            t1 = blocks2[j - 15];
            s0 = (t1 >>> 7 | t1 << 25) ^ (t1 >>> 18 | t1 << 14) ^ t1 >>> 3;
            t1 = blocks2[j - 2];
            s1 = (t1 >>> 17 | t1 << 15) ^ (t1 >>> 19 | t1 << 13) ^ t1 >>> 10;
            blocks2[j] = blocks2[j - 16] + s0 + blocks2[j - 7] + s1 << 0;
          }
          bc = b & c;
          for (j = 0; j < 64; j += 4) {
            if (this.first) {
              if (this.is224) {
                ab = 300032;
                t1 = blocks2[0] - 1413257819;
                h = t1 - 150054599 << 0;
                d = t1 + 24177077 << 0;
              } else {
                ab = 704751109;
                t1 = blocks2[0] - 210244248;
                h = t1 - 1521486534 << 0;
                d = t1 + 143694565 << 0;
              }
              this.first = false;
            } else {
              s0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
              s1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
              ab = a & b;
              maj = ab ^ a & c ^ bc;
              ch = e & f ^ ~e & g;
              t1 = h + s1 + ch + K2[j] + blocks2[j];
              t2 = s0 + maj;
              h = d + t1 << 0;
              d = t1 + t2 << 0;
            }
            s0 = (d >>> 2 | d << 30) ^ (d >>> 13 | d << 19) ^ (d >>> 22 | d << 10);
            s1 = (h >>> 6 | h << 26) ^ (h >>> 11 | h << 21) ^ (h >>> 25 | h << 7);
            da = d & a;
            maj = da ^ d & b ^ ab;
            ch = h & e ^ ~h & f;
            t1 = g + s1 + ch + K2[j + 1] + blocks2[j + 1];
            t2 = s0 + maj;
            g = c + t1 << 0;
            c = t1 + t2 << 0;
            s0 = (c >>> 2 | c << 30) ^ (c >>> 13 | c << 19) ^ (c >>> 22 | c << 10);
            s1 = (g >>> 6 | g << 26) ^ (g >>> 11 | g << 21) ^ (g >>> 25 | g << 7);
            cd = c & d;
            maj = cd ^ c & a ^ da;
            ch = g & h ^ ~g & e;
            t1 = f + s1 + ch + K2[j + 2] + blocks2[j + 2];
            t2 = s0 + maj;
            f = b + t1 << 0;
            b = t1 + t2 << 0;
            s0 = (b >>> 2 | b << 30) ^ (b >>> 13 | b << 19) ^ (b >>> 22 | b << 10);
            s1 = (f >>> 6 | f << 26) ^ (f >>> 11 | f << 21) ^ (f >>> 25 | f << 7);
            bc = b & c;
            maj = bc ^ b & d ^ cd;
            ch = f & g ^ ~f & h;
            t1 = e + s1 + ch + K2[j + 3] + blocks2[j + 3];
            t2 = s0 + maj;
            e = a + t1 << 0;
            a = t1 + t2 << 0;
            this.chromeBugWorkAround = true;
          }
          this.h0 = this.h0 + a << 0;
          this.h1 = this.h1 + b << 0;
          this.h2 = this.h2 + c << 0;
          this.h3 = this.h3 + d << 0;
          this.h4 = this.h4 + e << 0;
          this.h5 = this.h5 + f << 0;
          this.h6 = this.h6 + g << 0;
          this.h7 = this.h7 + h << 0;
        };
        Sha256.prototype.hex = function() {
          this.finalize();
          var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5, h6 = this.h6, h7 = this.h7;
          var hex = HEX_CHARS2[h0 >> 28 & 15] + HEX_CHARS2[h0 >> 24 & 15] + HEX_CHARS2[h0 >> 20 & 15] + HEX_CHARS2[h0 >> 16 & 15] + HEX_CHARS2[h0 >> 12 & 15] + HEX_CHARS2[h0 >> 8 & 15] + HEX_CHARS2[h0 >> 4 & 15] + HEX_CHARS2[h0 & 15] + HEX_CHARS2[h1 >> 28 & 15] + HEX_CHARS2[h1 >> 24 & 15] + HEX_CHARS2[h1 >> 20 & 15] + HEX_CHARS2[h1 >> 16 & 15] + HEX_CHARS2[h1 >> 12 & 15] + HEX_CHARS2[h1 >> 8 & 15] + HEX_CHARS2[h1 >> 4 & 15] + HEX_CHARS2[h1 & 15] + HEX_CHARS2[h2 >> 28 & 15] + HEX_CHARS2[h2 >> 24 & 15] + HEX_CHARS2[h2 >> 20 & 15] + HEX_CHARS2[h2 >> 16 & 15] + HEX_CHARS2[h2 >> 12 & 15] + HEX_CHARS2[h2 >> 8 & 15] + HEX_CHARS2[h2 >> 4 & 15] + HEX_CHARS2[h2 & 15] + HEX_CHARS2[h3 >> 28 & 15] + HEX_CHARS2[h3 >> 24 & 15] + HEX_CHARS2[h3 >> 20 & 15] + HEX_CHARS2[h3 >> 16 & 15] + HEX_CHARS2[h3 >> 12 & 15] + HEX_CHARS2[h3 >> 8 & 15] + HEX_CHARS2[h3 >> 4 & 15] + HEX_CHARS2[h3 & 15] + HEX_CHARS2[h4 >> 28 & 15] + HEX_CHARS2[h4 >> 24 & 15] + HEX_CHARS2[h4 >> 20 & 15] + HEX_CHARS2[h4 >> 16 & 15] + HEX_CHARS2[h4 >> 12 & 15] + HEX_CHARS2[h4 >> 8 & 15] + HEX_CHARS2[h4 >> 4 & 15] + HEX_CHARS2[h4 & 15] + HEX_CHARS2[h5 >> 28 & 15] + HEX_CHARS2[h5 >> 24 & 15] + HEX_CHARS2[h5 >> 20 & 15] + HEX_CHARS2[h5 >> 16 & 15] + HEX_CHARS2[h5 >> 12 & 15] + HEX_CHARS2[h5 >> 8 & 15] + HEX_CHARS2[h5 >> 4 & 15] + HEX_CHARS2[h5 & 15] + HEX_CHARS2[h6 >> 28 & 15] + HEX_CHARS2[h6 >> 24 & 15] + HEX_CHARS2[h6 >> 20 & 15] + HEX_CHARS2[h6 >> 16 & 15] + HEX_CHARS2[h6 >> 12 & 15] + HEX_CHARS2[h6 >> 8 & 15] + HEX_CHARS2[h6 >> 4 & 15] + HEX_CHARS2[h6 & 15];
          if (!this.is224) {
            hex += HEX_CHARS2[h7 >> 28 & 15] + HEX_CHARS2[h7 >> 24 & 15] + HEX_CHARS2[h7 >> 20 & 15] + HEX_CHARS2[h7 >> 16 & 15] + HEX_CHARS2[h7 >> 12 & 15] + HEX_CHARS2[h7 >> 8 & 15] + HEX_CHARS2[h7 >> 4 & 15] + HEX_CHARS2[h7 & 15];
          }
          return hex;
        };
        Sha256.prototype.toString = Sha256.prototype.hex;
        Sha256.prototype.digest = function() {
          this.finalize();
          var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5, h6 = this.h6, h7 = this.h7;
          var arr = [
            h0 >> 24 & 255,
            h0 >> 16 & 255,
            h0 >> 8 & 255,
            h0 & 255,
            h1 >> 24 & 255,
            h1 >> 16 & 255,
            h1 >> 8 & 255,
            h1 & 255,
            h2 >> 24 & 255,
            h2 >> 16 & 255,
            h2 >> 8 & 255,
            h2 & 255,
            h3 >> 24 & 255,
            h3 >> 16 & 255,
            h3 >> 8 & 255,
            h3 & 255,
            h4 >> 24 & 255,
            h4 >> 16 & 255,
            h4 >> 8 & 255,
            h4 & 255,
            h5 >> 24 & 255,
            h5 >> 16 & 255,
            h5 >> 8 & 255,
            h5 & 255,
            h6 >> 24 & 255,
            h6 >> 16 & 255,
            h6 >> 8 & 255,
            h6 & 255
          ];
          if (!this.is224) {
            arr.push(h7 >> 24 & 255, h7 >> 16 & 255, h7 >> 8 & 255, h7 & 255);
          }
          return arr;
        };
        Sha256.prototype.array = Sha256.prototype.digest;
        Sha256.prototype.arrayBuffer = function() {
          this.finalize();
          var buffer = new ArrayBuffer(this.is224 ? 28 : 32);
          var dataView = new DataView(buffer);
          dataView.setUint32(0, this.h0);
          dataView.setUint32(4, this.h1);
          dataView.setUint32(8, this.h2);
          dataView.setUint32(12, this.h3);
          dataView.setUint32(16, this.h4);
          dataView.setUint32(20, this.h5);
          dataView.setUint32(24, this.h6);
          if (!this.is224) {
            dataView.setUint32(28, this.h7);
          }
          return buffer;
        };
        function HmacSha256(key, is224, sharedMemory) {
          var i, type = typeof key;
          if (type === "string") {
            var bytes = [], length = key.length, index = 0, code;
            for (i = 0; i < length; ++i) {
              code = key.charCodeAt(i);
              if (code < 128) {
                bytes[index++] = code;
              } else if (code < 2048) {
                bytes[index++] = 192 | code >> 6;
                bytes[index++] = 128 | code & 63;
              } else if (code < 55296 || code >= 57344) {
                bytes[index++] = 224 | code >> 12;
                bytes[index++] = 128 | code >> 6 & 63;
                bytes[index++] = 128 | code & 63;
              } else {
                code = 65536 + ((code & 1023) << 10 | key.charCodeAt(++i) & 1023);
                bytes[index++] = 240 | code >> 18;
                bytes[index++] = 128 | code >> 12 & 63;
                bytes[index++] = 128 | code >> 6 & 63;
                bytes[index++] = 128 | code & 63;
              }
            }
            key = bytes;
          } else {
            if (type === "object") {
              if (key === null) {
                throw new Error(ERROR);
              } else if (ARRAY_BUFFER && key.constructor === ArrayBuffer) {
                key = new Uint8Array(key);
              } else if (!Array.isArray(key)) {
                if (!ARRAY_BUFFER || !ArrayBuffer.isView(key)) {
                  throw new Error(ERROR);
                }
              }
            } else {
              throw new Error(ERROR);
            }
          }
          if (key.length > 64) {
            key = new Sha256(is224, true).update(key).array();
          }
          var oKeyPad = [], iKeyPad = [];
          for (i = 0; i < 64; ++i) {
            var b = key[i] || 0;
            oKeyPad[i] = 92 ^ b;
            iKeyPad[i] = 54 ^ b;
          }
          Sha256.call(this, is224, sharedMemory);
          this.update(iKeyPad);
          this.oKeyPad = oKeyPad;
          this.inner = true;
          this.sharedMemory = sharedMemory;
        }
        HmacSha256.prototype = new Sha256();
        HmacSha256.prototype.finalize = function() {
          Sha256.prototype.finalize.call(this);
          if (this.inner) {
            this.inner = false;
            var innerHash = this.array();
            Sha256.call(this, this.is224, this.sharedMemory);
            this.update(this.oKeyPad);
            this.update(innerHash);
            Sha256.prototype.finalize.call(this);
          }
        };
        var exports2 = createMethod();
        exports2.sha256 = exports2;
        exports2.sha224 = createMethod(true);
        exports2.sha256.hmac = createHmacMethod();
        exports2.sha224.hmac = createHmacMethod(true);
        if (COMMON_JS) {
          module.exports = exports2;
        } else {
          root.sha256 = exports2.sha256;
          root.sha224 = exports2.sha224;
          if (AMD) {
            define(function() {
              return exports2;
            });
          }
        }
      })();
    }
  });

  // src/security.sha256.js
  var require_security_sha256 = __commonJS({
    "src/security.sha256.js"(exports, module) {
      var sha2562 = require_sha256();
      var hash = function(message) {
        if (message === void 0 || message === null) {
          throw new TypeError('The "message" argument must be a string');
        }
        return sha2562(String(message));
      };
      module.exports = {
        hash: async function(message) {
          if (message === void 0 || message === null) {
            throw new TypeError('The "message" argument must be a string');
          }
          const encoded = new TextEncoder().encode(String(message));
          const buffer = await globalThis.crypto.subtle.digest("SHA-256", encoded);
          return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
        },
        hashSync: hash
      };
    }
  });

  // src/utils.js
  var require_utils = __commonJS({
    "src/utils.js"(exports, module) {
      var DEFAULT_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      var generate = function(options) {
        if (typeof options === "number") {
          options = { length: options };
        }
        const opts = options || {};
        const length = opts.length || 32;
        const chars = opts.charset || DEFAULT_CHARSET;
        const bytes = new Uint8Array(length);
        globalThis.crypto.getRandomValues(bytes);
        return Array.from(bytes).map((b) => chars[b % chars.length]).join("");
      };
      var randomstring = {
        generate: async function(options) {
          return generate(options);
        },
        generateSync: generate
      };
      module.exports = { randomstring };
    }
  });

  // src/windowSfet.js
  window.sfet = {
    aes: require_security_aes(),
    md5: require_security_md5(),
    rsa: require_security_rsa(),
    sha256: require_security_sha256(),
    utils: require_utils()
  };
})();
/*! Bundled license information:

is-buffer/index.js:
  (*!
   * Determine if an object is a Buffer
   *
   * @author   Feross Aboukhadijeh <https://feross.org>
   * @license  MIT
   *)

js-sha256/src/sha256.js:
  (**
   * [js-sha256]{@link https://github.com/emn178/js-sha256}
   *
   * @version 0.10.1
   * @author Chen, Yi-Cyuan [emn178@gmail.com]
   * @copyright Chen, Yi-Cyuan 2014-2023
   * @license MIT
   *)
*/
