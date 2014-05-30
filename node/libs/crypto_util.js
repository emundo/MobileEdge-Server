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
 * @file Cryptographic utilities, such as HMAC and HKDF.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

const HKDF = require('hkdf'),
      crypto = require('crypto');
var mu = require('./util.js'); // My Util

/**
 * Compute an HMAC with a given key and data (message).
 * The inner and outer padding (ipad, opad) are based on the 
 * RFC2104 definition of HMAC (https://tools.ietf.org/html/rfc2104)
 *
 * ATTENTION: For some reason this differs from the HMAC implementation
 * in Node.crypto and until I know that this implementation is not
 * somehow flawed, _hmac below (which uses Node.crypto) should and will be used.
 * Node.crypto is also consistent with http://www.freeformatter.com/hmac-generator.html
 *
 * @param {Uint8Array} key - the secret key used for the HMAC
 * @param {string} data - the data to be embedded in the HMAC
 * @return {Uint8Array} - the HMAC created from key and data as 32 bytes
 */
function hmac(key, data) {
//    mu.debug("Hashing:", nacl.to_hex(key), data);
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

function _hmac(key, data) {
//    mu.debug("Hashing:", nacl.to_hex(key), data);
    var hmac = crypto.createHmac('sha256', nacl.to_hex(key));
    hmac.update(data);
    return hmac.digest();
}
exports.hmac =  _hmac;
exports._hmac = _hmac;
function hkdf(inputKeyMaterial, info, callback) {
    var hkdf = new HKDF('sha256', 'salty', inputKeyMaterial),
        result = {};
    hkdf.derive(info , 64, function(key) {
        key = key.toString('hex');
        result.first = key.substr(0, key.length / 2);
        result.last  = key.substr(key.length / 2);
        callback(result);
    });
}
exports.hkdf = hkdf;
