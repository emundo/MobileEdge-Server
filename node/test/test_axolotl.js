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
        /**
         * Test that Alice (the client) and Bob (the server) calculate the same secret.
         */
        it('Alice (client) and Bob (server) should calculate the same shared secret', function(done){
            var aliceParams = axolotl.genParametersAlice();
            var aliceKeyExchangeMsg = {    // extract public keys
                'id_mac': 'abcdtest',
                'id'    : nacl.to_hex(aliceParams['id']['boxPk']),
                'eph0'  : nacl.to_hex(aliceParams['eph0']['boxPk'])
            };
            var bobShared;
            var finish = function(err, aliceSharedSecret) {
                if (err) {
                    myutil.log(err);
                    throw new Error('Apparently Alice could not finish the key agreement.')
                } else {
                    expect(aliceSharedSecret).to.deep.equal(bobShared);
                    AxolotlState.remove({ id_mac : 'abcdtest'}).exec();
                    var promise = AxolotlState.find({ id_mac : 'abcdtest'}).exec();
                    promise.onFulfill(function (arg) {
                        expect(arg).to.be.empty;
                        done();
                    });
                }
            };
            axolotl.keyAgreement(aliceKeyExchangeMsg,
                function(err, ourKeyExchangeMsg, sharedSecret){
                    if (err) {
                        myutil.log(err);
                        myutil.log('Bob reports an error when trying to perform a key agreement.');
                        expect(err).to.not.exist;
                        done();
                    } else {
                        bobShared = sharedSecret;//{'first': sharedSecret.rk, 'last' : sharedSecret.ck };
                        axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, finish);
                    }
            });
        });
    });
});

/**
 * Tests for sending and receiving messages.
 */
describe('Message sending and receiving', function(){
    /**
     * Test the sendMessage() function (server) vs the recvMessage() function (client).
     * Valid AxolotlStates need to be set up before.
     */
    describe('#sendMessage() -> recvMessage()', function(){
        var stateAlice, stateBob;
        /**
         * Setup AxolotlStates for Alice and Bob via key agreement.
         */
        before(function(done) {
            function updateStateAlice(keysAlice, keyExchangeMsgBob) {
                stateAlice.root_key              = keysAlice.rk;
                stateAlice.chain_key_recv        = keysAlice.ck; // Alice is Client. So we set CKr first.
                stateAlice.header_key_recv       = keysAlice.hk;
                stateAlice.next_header_key_send  = keysAlice.nhk0;    //FIXME: invert
                stateAlice.next_header_key_recv  = keysAlice.nhk1;    // -"-
                stateAlice.dh_identity_key_send  = nacl.to_hex(aliceParams.id.boxSk);
                stateAlice.dh_identity_key_recv  = nacl.to_hex(keyExchangeMsgBob.id);
                stateAlice.dh_ratchet_key_recv   = nacl.to_hex(keyExchangeMsgBob.eph1);   // Storing secret (private) key here. Should we store the whole key pair instead?
                stateAlice.counter_send = 0;
                stateAlice.counter_recv = 0;
                stateAlice.previous_counter_send = 0;
                stateAlice.ratchet_flag = true;
            }
            var aliceParams = axolotl.genParametersAlice();
            var aliceKeyExchangeMsg = {    // extract public keys
                'id_mac': nacl.to_hex(nacl.encode_utf8('AliceID')),
                'id'    : nacl.to_hex(aliceParams['id']['boxPk']),
                'eph0'  : nacl.to_hex(aliceParams['eph0']['boxPk'])
            };
            axolotl.keyAgreement(aliceKeyExchangeMsg,
                function(err, ourKeyExchangeMsg, keys, state){
                    if (err) {
                        myutil.log(err);
                        myutil.log('Bob reports an error when trying to perform a key agreement.');
                    } else {
                        stateBob = state;
                        //myutil.debug('DEBUG: state of Bob after key agreement: ', stateBob);
                        axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, function(err, keys) {
                            if (err) {        
                                myutil.log(err);
                                throw new Error('Apparently Alice could not finish the key agreement.');
                            } else {
                                //TODO: set Alice's state
                                stateAlice = new AxolotlState();
                                stateAlice.id_mac = 'BobID';
                                updateStateAlice(keys, ourKeyExchangeMsg);
                            }
                        });
                    }
            });
            done();
        });
        it('first message to the client should be decryptable', function(done) {
            var message = "Hello World. I am a MobileEdge Axolotl test message.";
            //myutil.debug('DEBUG: state of Bob before 1st msg: ', stateBob);
            axolotl.sendMessage(stateBob, message, function(err, ciphertext, state) {
                //myutil.debug("DEBUG: got ciphertext:", ciphertext);
                expect(err, 'Error from Bob sending message').to.not.exist;
                //myutil.debug('DEBUG: state of Alice before 1st msg: ', stateAlice);
                stateBob = state;
                axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                    //myutil.debug("DEBUG: got ciphertext:", ciphertext);
                    expect(err, 'Error from Alice receiving message').to.not.exist;
                    myutil.debug("Plaintext:", plaintext);
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message);
                    stateAlice = state;
                });
            });
            done();
        });
        it('multiple messages to the client should be decryptable (no ratchet)', function(done) {
            var message = "Hello World. I am a MobileEdge Axolotl test message and I am sent repeatedly.";
            var message2 = "Hello World. I am a MobileEdge Axolotl test message and I am sent repeatedly (2).";
            //myutil.debug('DEBUG: state of Bob before 2nd msg: ', stateBob);
            axolotl.sendMessage(stateBob, message, function(err, ciphertext, state) {
                //myutil.debug("DEBUG: got ciphertext:", ciphertext);
                expect(err, 'Error from Bob sending message').to.not.exist;
                stateBob = state;
                //myutil.debug('DEBUG: state of Alice before 2nd msg: ', stateAlice);
                axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                    expect(err, 'Error from Alice receiving message').to.not.exist;
                    myutil.debug("Plaintext:", plaintext);
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message);
                    stateAlice = state;
                    axolotl.sendMessage(stateBob, message2, function(err, ciphertext, state) {
                        expect(err).to.not.exist;
                        stateBob = state;
                        axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                            expect(err).to.not.exist;
                            myutil.debug("Plaintext:", plaintext);
                            expect(plaintext).to.equal(message2);
                        });
                    });
                });
            });
            done();
        });
        afterEach(function(done){
            //TODO: delete test axolotl states
            done();
        });
    });
    /**
     * Test the recvMessage() function (server) vs the sendMessage() function (client).
     * Valid AxolotlStates need to be set up before. 
     * Additionally one message must be sent from the server to the client first, to complete
     * the first ratchet.
     */
    describe('#recvMessage() <- sendMessage()', function(){
        var stateAlice, stateBob;
        /**
         * Create AxolotlState.
         */
        before(function(done) {
            function updateStateAlice(keysAlice, keyExchangeMsgBob) {
                stateAlice.root_key              = keysAlice.rk;
                stateAlice.chain_key_recv        = keysAlice.ck; // Alice is Client. So we set CKr first.
                stateAlice.header_key_recv       = keysAlice.hk;
                stateAlice.next_header_key_send  = keysAlice.nhk0;    //FIXME: invert
                stateAlice.next_header_key_recv  = keysAlice.nhk1;    // -"-
                stateAlice.dh_identity_key_send  = nacl.to_hex(aliceParams.id.boxSk);
                stateAlice.dh_identity_key_recv  = nacl.to_hex(keyExchangeMsgBob.id);
                stateAlice.dh_ratchet_key_recv   = nacl.to_hex(keyExchangeMsgBob.eph1);   // Storing secret (private) key here. Should we store the whole key pair instead?
                stateAlice.counter_send = 0;
                stateAlice.counter_recv = 0;
                stateAlice.previous_counter_send = 0;
                stateAlice.ratchet_flag = true;
            }
            var aliceParams = axolotl.genParametersAlice();
            var aliceKeyExchangeMsg = {    // extract public keys
                'id_mac': nacl.to_hex(nacl.encode_utf8('AliceID')),
                'id'    : nacl.to_hex(aliceParams['id']['boxPk']),
                'eph0'  : nacl.to_hex(aliceParams['eph0']['boxPk'])
            };
            axolotl.keyAgreement(aliceKeyExchangeMsg,
                function(err, ourKeyExchangeMsg, keys, state){
                    if (err) {
                        myutil.log(err);
                        myutil.log('Bob reports an error when trying to perform a key agreement.');
                    } else {
                        stateBob = state;
                        //myutil.debug('DEBUG: state of Bob after key agreement: ', stateBob);
                        axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, function(err, keys) {
                            if (err) {        
                                myutil.log(err);
                                throw new Error('Apparently Alice could not finish the key agreement.');
                            } else {
                                //TODO: set Alice's state
                                stateAlice = new AxolotlState();
                                stateAlice.id_mac = 'BobID';
                                updateStateAlice(keys, ourKeyExchangeMsg);
                            }
                        });
                    }
            });
            done();
        });
        
        it('first message from the client should be decryptable', function(done) {
            var message = "Hello, I am a message from server to client.";
            var message2 = "Hello, I am an answer to a message. I am sent from client to server.";
            //myutil.debug('GUBED: state of Bob before 1st msg: ', stateBob);
            axolotl.sendMessage(stateBob, message, function(err, ciphertext, state) {
                //myutil.debug("GUBED: got ciphertext:", ciphertext);
                expect(err, 'Error from Bob sending message').to.not.exist;
                stateBob = state;
                //myutil.debug('GUBED: state of Alice before 1st msg: ', stateAlice);
                axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                    expect(err, 'Error from Alice receiving message').to.not.exist;
                    //myutil.debug("Plaintext:", plaintext);
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message);
                    stateAlice = state;
                    //myutil.debug('GUBED: state of Alice before 2nd msg: ', stateAlice);
                    axolotl.sendMessage(stateAlice, message2, function(err, ciphertext, state) {
                        expect(err).to.not.exist;
                        stateAlice = state;
                        //myutil.debug('GUBED: state of Alice after 2nd msg: ', stateAlice);
                        //myutil.debug('GUBED: state of Bob before 2nd msg: ', stateBob);
                        axolotl.recvMessage(stateBob, ciphertext, function(err, plaintext, state) {
                            expect(err).to.not.exist;
                            //myutil.debug('GUBED: state of Bob after 2nd msg: ', state);
                            myutil.debug("Plaintext:", plaintext);
                            stateBob = state;
                            expect(plaintext).to.equal(message2);
                        });
                    });
                });
            });
            done();
        });
        
        it('multiple messages from the client should be decryptable (no ratchet)', function(done) {
            var message3 = "Hello, I am _another_ message from client to server!";
            //myutil.debug('GUBED: state of Bob before 1st msg: ', stateBob);
            axolotl.sendMessage(stateAlice, message3, function(err, ciphertext, state) {
                //myutil.debug("GUBED: got ciphertext:", ciphertext);
                expect(err, 'Error from Alice sending 3rd message').to.not.exist;
                stateAlice = state;
                //myutil.debug('GUBED: state of Alice before 1st msg: ', stateAlice);
                axolotl.recvMessage(stateBob, ciphertext, function(err, plaintext, state) {
                    expect(err, 'Error from Alice receiving message').to.not.exist;
                    myutil.debug("Plaintext:", plaintext);
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message3);
                    stateBob = state;
                    //myutil.debug('GUBED: state of Alice before 2nd msg: ', stateAlice);
                });
            });
            done();
        });

        it('ratchet information should be successfully updated', function(done) {
            var message4 = "And this is a message from Bob. Ratchet should be done now.";
            var message5 = "Alices answer hopefully using the ratcheted keys."
            axolotl.sendMessage(stateBob, message4, function(err, ciphertext, state) {
                //myutil.debug("GUBED: got ciphertext:", ciphertext);
                expect(err, 'Error from Bob sending message').to.not.exist;
                stateBob = state;
                //myutil.debug('DEBUG ratchet: state of Alice before sending msg: ', stateAlice);
                axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                    expect(err, 'Error from Alice receiving message').to.not.exist;
                    myutil.debug("Plaintext:", plaintext);
                    expect(plaintext, 'message from Bob to Alice').to.equal(message4);
                    stateAlice = state;
                    //myutil.debug('DEBUG: state of Alice before last msg: ', stateAlice);
                    axolotl.sendMessage(stateAlice, message5, function(err,ciphertext,state){
                        expect(err, 'Error from Alice sending an answer after ratchet').to.not.exist;
                        stateAlice = state;
                        //myutil.debug('DEBUG: state of Alice after last msg: ', stateAlice);
                        //myutil.debug('DEBUG: state of Bob before last msg: ', stateBob);
                        axolotl.recvMessage(stateBob, ciphertext, function(err, plaintext, state) {
                            expect(err, 'Error from Bob receiving Alice\'s answer').to.not.exist;
                            stateBob = state;
                            //myutil.debug('DEBUG: state of Bob after last msg: ', stateBob);
                            myutil.debug("Plaintext:", plaintext);
                            expect(plaintext, 'message from Alice to Bob').to.equal(message5);
                        });
                    });
                });
            });
            done();
        });
        /**
         * Delete AxolotlState.
         */
        afterEach(function(done){
           done();
        });
    });
});


// To get an AxolotlState: AxolotlState.findOne({id_mac: from}).exec().onFulfill(function(result){
