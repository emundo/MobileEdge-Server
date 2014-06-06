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
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

var expect = require('chai').expect,
    main = require('../main.js'),
    token = require('../libs/token.js'),
    crypto = require('crypto'),
    cu = require('../libs/crypto_util.js'),
    myutil = require('../libs/util.js');

/**
 * Tests for HMAC functionality.
 */
describe('HMAC functionality', function(){
    /**
     * Test the crypto_util HMAC function.
     */
    describe('#hmac()', function(){
        /**
         * The crypto_util hmac function (using NaCl) should yield the same
         * result as the crypto_util _hmac function (using Node's own crypto
         * module.
         */
        it('should equal crypto builtin hmac', function(){
            // generate a random key every time
            var key = nacl.random_bytes(40);
            var attempt = cu.hmac(key, 'MobileEdge is a great thing'),
                other = cu._hmac(key, 'MobileEdge is a great thing');
            myutil.debug('comparing HMACs:', nacl.to_hex(attempt), nacl.to_hex(other));
            expect(nacl.to_hex(attempt)).to.equal(nacl.to_hex(other));
        });
    });
});

/**
 * Tests for Token creation.
 */
describe('Token Creation', function(){
    /**
     * Test the create_id functionality.
     */
    describe('#create_id()', function(){
        /**
         * Make sure the create_id function returns a token object.
         */
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

/**
 * Tests for creation and verification.
 */
describe('Token creation & verification', function(){
    /**
     * Test create vs verify.
     */
    describe('#create_id() & verify_id()', function(){
        /**
         * Check the created token is recognized as valid by the verify() function.
         */
        it('created token should be valid', function(done){
            var new_id;
            token.create_id(function(id) {
                token.verify_id(id, function (result) {
                    expect(result).to.equal(token.VALID);
                });
            });
            done();
        });
    });

    /**
     * Combine create, refresh and verify.
     */
    describe('# create_id() & refresh_id() & verify_id()', function(){
        /**
         * Test that the created token can be refreshed and the result of
         * refreshing is again a valid token.
         */
        it('created token should be able to be refreshed and the result should be valid', function(done){
            var old_id, new_id;
            token.create_id(function(old_id){
                token.refresh_id(old_id, function(new_id) {
                    expect(new_id.info.previous, 'correct reference to old mac').to.equal(old_id.mac);
                    token.verify_id(new_id, function(result) {
                        expect(result, 'validity').to.equal(token.VALID);
                    })
                })
            });
            done();
        });
    });
});
