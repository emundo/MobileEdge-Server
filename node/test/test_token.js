/*
 * This file is part of MobileEdge-Server, the server-side component
 * of the MobileEdge framework.
 * Copyright (c) 2014 eMundo GmbH

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
    myutil = require('../libs/util.js'),
    sodium = require('sodium').api;

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
            var key = new Buffer (40);
            sodium.randombytes(key);
            var attempt = cu.hmac(key, 'MobileEdge is a great thing'),
                other = cu._hmac(key, 'MobileEdge is a great thing');
            myutil.debug(attempt, other);
            expect(sodium.memcmp(attempt,other,32)).to.equal(0);
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
