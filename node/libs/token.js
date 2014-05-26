/**
 * @file Implements token-related operations like token creation.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */
var nacl_factory = require("js-nacl");
var nacl = nacl_factory.instantiate();
var myutil = require("./util.js");
var util = require('util');
myutil.debug(nacl.to_hex(nacl.random_bytes(16)));

var cv = nacl.encode_utf8
var toHex = nacl.to_hex

var key = cv("d2cf52201f5fe179a9174b3925351159")

/**
 * Creates an ID-Token from data and calls a given callback function
 * to hand this token back.
 * Beware: The argument data is not checked, nor is it filled with appropriate
 * data, such as a Nonce/Timestamp. This should be taken care of from the
 * calling function.
 * @param data - data to be included into token
 * @param callback - callback function to be called when token was generated.
 *      It takes one argument, the token that was created.
 */
function _create_id(data, callback) {
    var token = {
        'info' : data,
        'mac' : toHex(hmac(key, JSON.stringify(data)))
    }; 
    callback(token);
}

/**
 * Create a 'new' identity with expiry date in a week's time.
 * To prevent information leakage through generation time information,
 * the expiry time is always set to 00:00:00:00.
 * @param callback - the function to call when finished with token generation.
 *      It takes one argument, the token that was created.
 */
function create_id(callback) {
    var expiry = new Date();
    expiry.setDate(expiry.getDate() + 7);
    expiry.setHours(0); expiry.setMinutes(0); expiry.setSeconds(0);
    expiry.setMilliseconds(0);
    var data = {'expires'   : expiry,
                'nonce'     : toHex(nacl.crypto_box_random_nonce())};
    var token = _create_id(data, callback);
}
exports.create_id = create_id;

/**
 * Verify a given identity token. 
 * Is it valid, i.e.
 *  Does the info match the HMAC?
 *  Has it expired? 
 * @param token - the token to be verified.
 * @param callback - the function to call when token was verified.
 *      It takes 1 argument, the result of the verification, which can
 *      be either "EXPIRED", "INVALID" or "VALID".
 */
function verify_id(token, callback) {
    myutil.debug('Verifying token:', token);
    if (token['info']['expires'] < new Date())
        callback('EXPIRED');
    if (token['mac'] === toHex(hmac(key, JSON.stringify(token['info'])))) {
        myutil.log('ok.');
        callback('VALID');
    } else {
        callback('INVALID');
    }
}
exports.verify_id = verify_id;

/**
 * Compute an HMAC with a given key and data (message).
 * The inner and outer padding (ipad, opad) are based on the 
 * RFC2104 definition of HMAC (https://tools.ietf.org/html/rfc2104) 
 * @param {Uint8Array} key - the secret key used for the HMAC
 * @param {string} data - the data to be embedded in the HMAC
 * @return {Uint8Array} - the HMAC created from key and data as 32 bytes
 */
function hmac(key, data) {
    var opad = new Uint8Array(64); 
    for (var i = 0; i < opad.length; i++)
        opad[i] = 0x5c;
    var ipad = new Uint8Array(64); 
    for (var i = 0; i < ipad.length; i++)
        ipad[i] = 0x5c;
    return nacl.crypto_hash_sha256(cv(myutil.xor(key,opad) + toHex(nacl.crypto_hash_sha256(cv(toHex(myutil.xor(key, ipad)) + data)))));
}

