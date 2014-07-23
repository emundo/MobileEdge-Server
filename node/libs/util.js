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
 * @file Util functions
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

var util = require('util');

/**
 * Checks if variable is a String. Why create a function for this? Well... JavaScript...
 * @param {*} s - the potential string
 * @return {Boolean} - true if s is a string object or of type string
 */
exports.isString = function isString(s) {
    return typeof(s) === 'string' || s instanceof String;
}

/**
 * Handmade bitwise xor for special non-integer types. JavaScript only correctly
 * performs ^ on ints.
 * Works for Strings and Uint8Array so far.
 * @param a - one item to be xored to
 * @param b - the other item
 * @return {string|Uint8Array} - the XORed result
 */
exports.xor = function xor(a, b) {
    var result;
    if (a instanceof Uint8Array && b instanceof Uint8Array) {
        var len = Math.max(a.length, b.length);
        result = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            result[i] = ((i >= a.length)? 0 : a[i]) ^ ((i >= b.length)? 0 : b[i]);
        }
    } else if (isString(a) && isString(b)) {
        var len = Math.max(a.length, b.length);
        result = "";
        for (var i = 0; i < len; i++) {
            result += String.fromCharCode(((i >= a.length)? 0 : a.charCodeAt(i)) ^ ((i >= b.length)? 0 : b.charCodeAt(i)));
        }
    } else {
        log("I dont know how to xor these types...");
    }
    return result;
}

/**
 * Map a function over an object, i.e. for each obj['key'] update the value to be f(value).
 * This is not type safe, of course (why would it be, this is JavaScript...). 
 * Close attention has to be paid to only calling this on objects where it is applicable,
 * i.e. all fields have the same type and values that don't cause trouble
 * with the function f.
 *
 * @param f - the function to map over the object
 * @param obj - the object the function should be mapped over
 * @return the modified object 
 */
exports.map = function map(f, obj) {
    for(var item in obj) {
        obj[item] = f(obj[item]);
    }
    return obj;
};
var log = exports.log = console.log;

var debug = exports.debug = console.log;

