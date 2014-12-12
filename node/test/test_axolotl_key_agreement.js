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
 * @file Test file for the axolotl protocol.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */
var expect = require('chai').expect,
    main = require('../main.js'),
    token = require('../libs/token.js'),
    axolotl = require('../libs/axolotl.js'),
    prekey = require('../libs/prekey.js'),
    myutil = require('../libs/util.js'),
    mongoose = require('mongoose');
var AxolotlState = mongoose.model('AxolotlState');

/**
 * Tests for the key agreement process.
 */
describe('Key agreement', function(){
    /**
     * Test keyAgreement vs keyAgreementAlice.
     */
    describe('#keyAgreement()', function(){
        var aliceParams, aliceKeyExchangeMsg;
        
        before(function(){
            aliceParams = axolotl.genParametersAlice();
            aliceKeyExchangeMsg = {    // extract public keys
                'id'    : aliceParams['id']['publicKey'],
                'eph0'  : aliceParams['eph0']['publicKey']
            }
        });

        /**
         * Test that Alice (the client) and Bob (the server) calculate the same secret.
         */
        it('Alice (client) and Bob (server) should calculate the same shared secret', function(done){
            var bobShared;
            var finish = function(err, aliceSharedSecret) {
                expect(err, 'Alice finishes key agreement').to.not.exist;
                expect(aliceSharedSecret, 'shared secrets deep equal').to.deep.equal(bobShared);
                done();
            };
            axolotl.keyAgreement(aliceKeyExchangeMsg, function(err, ourKeyExchangeMsg, sharedSecret){
                expect(err, 'Bob finishes key agreement').to.not.exist;
                bobShared = sharedSecret;
                axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, finish);
            });
        });

        after(function(done){
            AxolotlState.remove({ dh_identity_key_recv : aliceParams.id.publicKey}).exec();
            var promise = AxolotlState.find({ dh_identity_key_recv : aliceParams.id.publicKey}).exec();
            promise.onFulfill(function (arg) {
                expect(arg, 'id_mac removed successfully').to.be.empty;
                done();
            });
        });
    });
});



// To get an AxolotlState: AxolotlState.findOne({id_mac: from}).exec().onFulfill(function(result){
