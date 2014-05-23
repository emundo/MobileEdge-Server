/**
 * @file Util functions
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

/**
 * Checks if variable is a String. Why create a function for this? Well... JavaScript...
 * @param {*} s - the potential string
 */
function isString(s) {
    return typeof(s) === 'string' || s instanceof String;
}

/**
 * Handmade bitwise xor for special non-integer types. JavaScript only correctly
 * performs ^ on ints.
 * Works for Strings and Uint8Array so far.
 * @param a - one item to be xored to
 * @param b - the other item
 */
function xor(a, b) {
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
        console.log("I dont know how to xor these types...");
    }
    return result;
}

exports.isString = isString;
exports.xor = xor;
