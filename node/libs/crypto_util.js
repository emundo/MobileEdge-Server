/*
 * Copyright (c) 2014 eMundo GmbH
 * All Rights Reserved.
 *
 * This software is the confidential and proprietary information of
 * eMundo GmbH. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it
 * only in accordance with the terms of the license agreement you
 * entered into with eMundo GmbH.
 *
 * Created by Raphael Arias on 2014-06-02.
 */
/**
 * @module crypto_util
 * @description Cryptographic utilities, such as HMAC and HKDF.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

const HKDF = require('hkdf'),
      crypto = require('crypto'),
      sodium = require('sodium').api;
var mu = require('./util.js'); // My Util

/**
 * @description Compute an HMAC with a given key and data (message).
 * The inner and outer padding (ipad, opad) are based on the 
 * RFC2104 definition of HMAC (https://tools.ietf.org/html/rfc2104)
 *
 * ATTENTION: For some reason this used to differ from the HMAC implementation
 * using Node.crypto (below, _hmac). It now seems to be consistent, although none of the
 * implementations match http://www.freeformatter.com/hmac-generator.html , but that 
 * might be their fault.
 *
 * @param {Uint8Array} key - the secret key used for the HMAC
 * @param {String} data - the data to be embedded in the HMAC
 * @return {Uint8Array} - the HMAC created from key and data as 32 bytes
 */
/*
exports.hmac = function hmac(key, data) {
    //mu.debug("Hashing:", nacl.to_hex(key), data);
    var opad = new Uint8Array(64), // outer padding
        ipad = new Uint8Array(64); // inner padding 
    for (var i = 0; i < opad.length; i++)
        opad[i] = 0x5c;
    for (var i = 0; i < ipad.length; i++)
        ipad[i] = 0x36;
    var innerParam = nacl.to_hex(mu.xor(key, ipad)) + nacl.to_hex(nacl.encode_utf8(data)),
        innerHash = nacl.crypto_hash_sha256(nacl.from_hex(innerParam)),
        outerParam = nacl.to_hex(mu.xor(key, opad)) + nacl.to_hex(innerHash);
    return nacl.crypto_hash_sha256(nacl.from_hex(outerParam));
}
*/
exports.hmac = function hmac(key, data) {
    //mu.debug("Hashing:", nacl.to_hex(key), data);
    var opad = new Buffer(64), // outer padding
        ipad = new Buffer(64); // inner padding 
    for (var i = 0; i < opad.length; i++)
        opad[i] = 0x5c;
    for (var i = 0; i < ipad.length; i++)
        ipad[i] = 0x36;
    var innerParam = Buffer.concat([mu.xor(key, ipad), new Buffer(data)]),
        innerHash = sodium.crypto_hash_sha256(innerParam),
        outerParam = Buffer.concat([mu.xor(key, opad), innerHash]);
    return sodium.crypto_hash_sha256(outerParam);
}

function _hmac(key, data) {
    //mu.debug("Hashing:", nacl.to_hex(key), data);
    //var hmac = crypto.createHmac('sha256', nacl.to_hex(key));// might decode_latin1 be better here?
    var hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest();
}
exports._hmac = _hmac;

/**
 * @callback module:crypto_util.KeyDeriveCallback
 * @param {String} key - the derived key material
 */
/**
 * @description Derives keys using HKDF.
 *
 * @param {Uint8Array} inputKeyMaterial the input key material
 * @param {String} info info to be woven into key derivation
 * @param {Number} length the length of the key material to be derived
 * @param {module:crypto_util.KeyDeriveCallback} callback the function
 *  to call with the key when finished
 */
exports.hkdf = function hkdf(inputKeyMaterial, info, length, callback) {
    inputKeyMaterial = nacl.decode_latin1(inputKeyMaterial);
    var hkdf = new HKDF('sha256', 'salty', inputKeyMaterial),
        result = {};
    hkdf.derive(info , length, function(key) {
        //key = key.toString('hex');
        callback(key);
    });
}
