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
 */
var expect = require('chai').expect,
    main = require('../main.js'),
    token = require('../libs/token.js'),
    axolotl = require('../libs/axolotl.js'),
    myutil = require('../libs/util.js'),
    mongoose = require('mongoose');

//var conn = mongoose.connect('mongodb://localhost/keys');
describe('Key agreement', function(){
describe('#keyAgreement()', function(){
    it('Alice (client) and Bob (server) should calculate the same shared secret', function(){
            var aliceParams = axolotl.genParametersAlice();
            var aliceKeyExchangeMsg = {    // extract public keys
                'id'    : nacl.to_hex(aliceParams['id']['boxPk']),
                'eph0'  : nacl.to_hex(aliceParams['eph0']['boxPk'])
            };
            var bobShared;
            var finish = function(err, aliceSharedSecret) {
                if (err) {
                    myutil.log(err);
                //    return new Error('Apparently Alice could not finish the key agreement.')
                } else {
                    //myutil.debug('shared secret (Alice):', aliceSharedSecret);
                    expect(aliceSharedSecret).to.deep.equal(bobShared);
                }
            };
            axolotl.keyAgreement(aliceKeyExchangeMsg,
                function(err, ourKeyExchangeMsg, sharedSecret){
                    if (err) {
                        myutil.log(err);
                    //    return new Error('Bob reports an error when trying to perform a key agreement.');
                    } else {
                        //myutil.debug('shared secret (Bob):', sharedSecret);
                        bobShared = sharedSecret;
                        axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, finish)
                    }
            });
        });
    });
});
//conn.connection.close();
