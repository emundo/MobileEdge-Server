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
                'id_mac': 'abcddead',
                'id'    : nacl.to_hex(aliceParams['id']['boxPk']),
                'eph0'  : nacl.to_hex(aliceParams['eph0']['boxPk'])
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
            AxolotlState.remove({ id_mac : 'abcddead'}).exec();
            var promise = AxolotlState.find({ id_mac : 'abcddead'}).exec();
            promise.onFulfill(function (arg) {
                expect(arg, 'id_mac removed successfully').to.be.empty;
                done();
            });
        });
    });
});



// To get an AxolotlState: AxolotlState.findOne({id_mac: from}).exec().onFulfill(function(result){
