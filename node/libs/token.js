/**
 * @file Implements token-related operations like token creation.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */
var nacl_factory = require("js-nacl");
var nacl = nacl_factory.instantiate();
var util = require("./util.js");
console.log(nacl.to_hex(nacl.random_bytes(16)));

cv = nacl.encode_utf8
toHex = nacl.to_hex

key = cv("d2cf52201f5fe179a9174b3925351159")

/**
 * Creates an ID-Token from data and calls a given callback function
 * to hand this token back.
 * Beware: The argument data is not checked, nor is it filled with appropriate
 * data, such as a Nonce/Timestamp. This should be taken care of from the
 * calling function, yet to define.
 * @param data - data to be included into token
 * @param callback - callback function to be called when token was generated.
 */
function create_id(data, callback) {
    token = {
        'info' : data,
        'mac' : toHex(hmac(key, data))
    }; 
    return token; //TODO: change this to callback(token);
}

/**
 * Compute an HMAC with a given key and data (message).
 * The inner and outer padding (ipad, opad) are based on the 
 * RFC2104 definition of HMAC (https://tools.ietf.org/html/rfc2104) 
 * @param {Uint8Array} key - the secret key used for the HMAC
 * @param {string} data - the data to be embedded in the HMAC
 * @return {Uint8Array} - the HMAC created from key and data as 64 bytes
 */
function hmac(key, data) {
    opad = new Uint8Array(64); 
    for (var i = 0; i < opad.length; i++)
        opad[i] = 0x5c;
    ipad = new Uint8Array(64); 
    for (var i = 0; i < ipad.length; i++)
        ipad[i] = 0x5c;

    return nacl.crypto_hash_sha256(cv(util.xor(key,opad) + nacl.crypto_hash_sha256(cv(toHex(util.xor(key, ipad)) + data))));
}

exports.create_id = create_id;
