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
 * @module util
 * @description Util functions
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

var util = require('util');

/**
 * @description
 * util log function. This is a wrapper for console.log() at the moment, 
 * but might be changed to a log to file or some logger functionality later.
 * Takes a variable length list of parameters.
 *
 * @function log
 * @static
 */
exports.log = console.log;

/**
 * @description
 * util debug log function. This is a wrapper for console.log() at the moment, 
 * but might be changed to a log to file, to a NOOP or some logger functionality later.
 * Takes a variable length list of parameters.
 *
 * @function debug
 * @static
 */
exports.debug = console.log;
//exports.debug = function() {};
/**
 * @description
 * Checks if variable is a String. Why create a function for this? Well... JavaScript...
 *
 * @param {*} s - the potential string
 * @return {Boolean} true if s is a string object or of type string
 */
exports.isString = 
function isString(s) {
    return typeof(s) === 'string' || s instanceof String;
}

/**
 * @description
 * Handmade bitwise xor for special non-integer types. JavaScript only correctly
 * performs ^ on ints.
 * Works for Strings and Uint8Array so far. Both parameters must have the same type
 *
 * @param {String|Uint8Array} a - one item to be xored to
 * @param {String|Uint8Array} b - the other item
 * @return {string|Uint8Array} the XORed result
 */
exports.xor = function xor(a, b) {
    var result;
    if (    (a instanceof Uint8Array || a instanceof Buffer) 
         && (b instanceof Uint8Array || b instanceof Buffer)) {
        var len = Math.max(a.length, b.length);
        result = new Buffer(len);
        for (var i = 0; i < len; i++) {
            result[i] = ((i >= a.length)? 0 : a[i]) ^ ((i >= b.length)? 0 : b[i]);
        }
    } else if (exports.isString(a) && exports.isString(b)) {
        var len = Math.max(a.length, b.length);
        result = "";
        for (var i = 0; i < len; i++) {
            result += String.fromCharCode(((i >= a.length)? 0 : a.charCodeAt(i)) ^ ((i >= b.length)? 0 : b.charCodeAt(i)));
        }
    } else {
        exports.log("I dont know how to xor these types...");
    }
    return result;
}

/**
 * @description
 * Map a function over an object, i.e. for each obj['key'] update the value to be f(value).
 * This is not type safe, of course (why would it be, this is JavaScript...). 
 * Close attention has to be paid to only calling this on objects where it is applicable,
 * i.e. all fields have the same type and values that don't cause trouble
 * with the function f.
 * Note that this changes the references to properties mapped over in the given object, 
 * thus not creating a copy as might be expected.
 *
 * @param {Function} f - the function to map over the object
 * @param {*} obj - the object the function should be mapped over
 * @return {*} the modified object 
 */
exports.map = function map(f, obj) {
    for(var item in obj) {
        obj[item] = f(obj[item]);
    }
    return obj;
};

/**
 * @description
 *  Convert a string with hexadecimal representation to base64 format.
 * @param {String} hexString - the hexadecimal string
 * @return {String} the base64 encoded string
 */
exports.hexToBase64 = function hexToBase64(hexString) {
    var b = new Buffer(hexString, 'hex');
    return b.toString('base64');
}

/**
 * @description
 *  Convert a string with base64 format to hexadecimal representation.
 * @return {String} base64String - the base64 encoded string
 * @return {String} the hexadecimal string
 */
exports.base64ToHex = function base64ToHex(base64String) {
    var b = new Buffer(base64String, 'base64');
    return b.toString('hex');
}
