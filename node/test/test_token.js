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
 * @file Testing for the token-related functionality.
 */
var expect = require('chai').expect,
    main = require('../main.js'),
    token = require('../libs/token.js'),
    crypto = require('crypto'),
    cu = require('../libs/crypto_util.js'),
    myutil = require('../libs/util.js');

describe('HMAC functionality', function(){
    describe('#hmac()', function(){
        it('should equal crypto builtin hmac', function(){
            var key = nacl.encode_utf8('key'),
                attempt = cu.hmac(key, ''),
                other = cu._hmac(key, '');
            myutil.debug(nacl.to_hex(attempt), nacl.to_hex(other));
            expect(nacl.to_hex(attempt)).to.equal(nacl.to_hex(other));
     //           hmac = crypto.createHmac('sha256', nacl.to_hex('000000'));
     //       hmac.update('');
     //       var comp = hmac.digest();
     //       myutil.log(comp);
     //       expect(myutil.toHex(attempt)).to.equal(comp.toString('hex'));
        });
    });
});

describe('Token Creation', function(){
    describe('#create_id()', function(){
        it('should return an ID token object', function(){
            token.create_id(function(new_token){
                myutil.debug(new_token);
                expect(new_token.info, 'property: expires').to.have.property('expires');
                expect(new_token.info, 'property: nonce').to.have.property('nonce').with.length(48);
                expect(new_token.mac, 'mac length').to.have.length(64);
            });
        });
    });
});

describe('Token creation & verification', function(){
    describe('#create_id() & verify_id()', function(){
        it('created token should be valid', function(){
            var new_id;
            token.create_id(function(id) {
                new_id = id; 
            });
            token.verify_id(new_id, function (result) {
                expect(result).to.equal(token.VALID);
            });
           
        });
    });
    describe('# create_id() & refresh_id() & verify_id()', function(){
        it('created token should be able to be refreshed and the result should be valid', function(){
            var old_id, new_id;
            token.create_id(function(id) {
                old_id = id; 
            });
            token.refresh_id(old_id, function(id) {
                new_id = id; 
            });
            token.verify_id(new_id, function (result) {
                expect(result, 'validity').to.equal(token.VALID);
            });
            expect(new_id.info.previous, 'correct reference to old mac').to.equal(old_id.mac);
        });
    });
});
