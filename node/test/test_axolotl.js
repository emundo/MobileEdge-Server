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
                if (err) {
                    myutil.log(err);
                    throw new Error('Apparently Alice could not finish the key agreement.')
                } else {
                    expect(aliceSharedSecret, 'shared secrets deep equal').to.deep.equal(bobShared);
                }
            };
            axolotl.keyAgreement(aliceKeyExchangeMsg,
                function(err, ourKeyExchangeMsg, sharedSecret){
                    if (err) {
                        myutil.log(err);
                        myutil.log('Bob reports an error when trying to perform a key agreement.');
                        expect(err, 'Bob agrees on key').to.not.exist;
                        done();
                    } else {
                        bobShared = sharedSecret;//{'first': sharedSecret.rk, 'last' : sharedSecret.ck };
                        axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, finish);
                    }
            });
            done();
        });

        after(function(done){
            AxolotlState.remove({ id_mac : 'abcddead'}).exec();
            var promise = AxolotlState.find({ id_mac : 'abcddead'}).exec();
            promise.onFulfill(function (arg) {
                expect(arg, 'id_mac removed successfully').to.be.empty;
            });
            done();
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
                        axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, function(err, keys) {
                            if (err) {        
                                myutil.log(err);
                                throw new Error('Apparently Alice could not finish the key agreement.');
                            } else {
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
            axolotl.sendMessage(stateBob, message, function(err, ciphertext, state) {
                expect(err, 'Error from Bob sending message').to.not.exist;
                stateBob = state;
                axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
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
            axolotl.sendMessage(stateBob, message, function(err, ciphertext, state) {
                expect(err, 'Error from Bob sending message').to.not.exist;
                stateBob = state;
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
        after(function(done){
            AxolotlState.remove({ _id : stateBob._id }, function(){
            });
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
                stateAlice.next_header_key_send  = keysAlice.nhk0;
                stateAlice.next_header_key_recv  = keysAlice.nhk1;
                stateAlice.dh_identity_key_send  = nacl.to_hex(aliceParams.id.boxSk);
                stateAlice.dh_identity_key_recv  = nacl.to_hex(keyExchangeMsgBob.id);
                stateAlice.dh_ratchet_key_recv   = nacl.to_hex(keyExchangeMsgBob.eph1);
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
                        myutil.log('Bob reports an error when trying to perform a key agreement! Duplicate keys?');
                    } else {
                        stateBob = state;
                        axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, function(err, keys) {
                            if (err) {        
                                myutil.log(err);
                                throw new Error('Apparently Alice could not finish the key agreement.');
                            } else {
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
            axolotl.sendMessage(stateBob, message, function(err, ciphertext, state) {
                expect(err, 'Error from Bob sending message').to.not.exist;
                stateBob = state;
                axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                    expect(err, 'Error from Alice receiving message').to.not.exist;
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message);
                    stateAlice = state;
                    axolotl.sendMessage(stateAlice, message2, function(err, ciphertext, state) {
                        expect(err).to.not.exist;
                        stateAlice = state;
                        axolotl.recvMessage(stateBob, ciphertext, function(err, plaintext, state) {
                            expect(err).to.not.exist;
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
            axolotl.sendMessage(stateAlice, message3, function(err, ciphertext, state) {
                expect(err, 'Error from Alice sending 3rd message').to.not.exist;
                stateAlice = state;
                axolotl.recvMessage(stateBob, ciphertext, function(err, plaintext, state) {
                    expect(err, 'Error from Alice receiving message').to.not.exist;
                    myutil.debug("Plaintext:", plaintext);
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message3);
                    stateBob = state;
                });
            });
            done();
        });

        it('ratchet information should be successfully updated', function(done) {
            var message4 = "And this is a message from Bob. Ratchet should be done now.";
            var message5 = "Alices answer hopefully using the ratcheted keys.";
            axolotl.sendMessage(stateBob, message4, function(err, ciphertext, state) {
                expect(err, 'Error from Bob sending message').to.not.exist;
                stateBob = state;
                axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                    expect(err, 'Error from Alice receiving message').to.not.exist;
                    myutil.debug("Plaintext:", plaintext);
                    expect(plaintext, 'message from Bob to Alice').to.equal(message4);
                    stateAlice = state;
                    axolotl.sendMessage(stateAlice, message5, function(err,ciphertext,state){
                        expect(err, 'Error from Alice sending an answer after ratchet').to.not.exist;
                        stateAlice = state;
                        axolotl.recvMessage(stateBob, ciphertext, function(err, plaintext, state) {
                            expect(err, 'Error from Bob receiving Alice\'s answer').to.not.exist;
                            stateBob = state;
                            myutil.debug("Plaintext:", plaintext);
                            expect(plaintext, 'message from Alice to Bob').to.equal(message5);
                        });
                    });
                });
            });
            done();
        });
        it('interleaved messages should be decrypted correctly', function(done){
            var message6 = "I will send two messages, receive an answer and send another one.";
            var message7 = "I will send one more message, wait for an answer and send another one.";
            var message8 = "This is the aforementioned answer...";
            var message9 = "I have received the answer. Sending this message now.";
            axolotl.sendMessage(stateBob, message6, function(err, ciphertext, state) {
                expect(err, 'Error from Bob sending message').to.not.exist;
                stateBob = state;
                axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                    expect(err, 'Error from Alice receiving first message').to.not.exist;
                    myutil.debug("Plaintext:", plaintext);
                    expect(plaintext, 'message from Bob to Alice').to.equal(message6);
                    stateAlice = state;
                    axolotl.sendMessage(stateBob, message7, function(err,ciphertext,state){
                        expect(err, 'Error from Bob sending second message').to.not.exist;
                        stateBob = state;
                        axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state) {
                            expect(err, 'Error from Alice receiving Bob\'s second message').to.not.exist;
                            stateAlice = state;
                            myutil.debug("Plaintext:", plaintext);
                            expect(plaintext, 'second message from Bob to Alice').to.equal(message7);
                            axolotl.sendMessage(stateAlice, message8, function(err, ciphertext, state) {
                                expect(err, 'Error from Alice sending answer').to.not.exist;
                                stateAlice = state;
                                axolotl.recvMessage(stateBob, ciphertext, function(err, plaintext, state){
                                    expect(err, 'Error from Bob receiving Alice\'s answer').to.not.exist;
                                    stateBob = state;
                                    myutil.debug('Plaintext:', plaintext);
                                    expect(plaintext, 'answer from Alice').to.equal(message8);
                                    axolotl.sendMessage(stateBob, message9, function(err, ciphertext, state){
                                        expect(err, 'Error from Bob sending 3rd message').to.not.exist;
                                        stateBob = state;
                                        axolotl.recvMessage(stateAlice, ciphertext, function(err, plaintext, state){
                                            expect(err, 'Error from Alice receiving Bob\'s 3rd message').to.not.exist;
                                            stateAlice = stateAlice;
                                            myutil.debug('Plaintext:', plaintext);
                                            expect(plaintext, '3rd message from Bob').to.equal(message9);
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
            done();
        });
        it('skipped messages should be decrypted fine', function(done){
            var message1 = "This is my first message, but it will arrive second.";
            var message2 = "This is my second message, but it will arrive first.";
            axolotl.sendMessage(stateBob, message1, function(err, ciphertext1, state) {
                expect(err, 'Error from Bob sending 1st message').to.not.exist;
                stateBob = state;
                axolotl.sendMessage(stateBob, message2, function(err,ciphertext2,state){
                    expect(err, 'Error from Bob sending 2nd message').to.not.exist;
                    stateBob = state;
                    axolotl.recvMessage(stateAlice, ciphertext2, function(err, plaintext, state) {
                        expect(err, 'Error from Alice receiving 2nd message').to.not.exist;
                        myutil.debug("Plaintext:", plaintext);
                        expect(plaintext, '2nd message from Bob to Alice').to.equal(message2);
                        stateAlice = state;
                        axolotl.recvMessage(stateAlice, ciphertext1, function(err, plaintext, state) {
                            expect(err, 'Error from Alice receiving 1st message').to.not.exist;
                            stateAlice = state;
                            myutil.debug("Plaintext:", plaintext);
                            expect(plaintext, '1st message from Bob to Alice').to.equal(message1);
                        });
                    });
                });
            });
            done();
        });
        it('skipped messages with ratchet in between should be decrypted fine', function(done){
            var message1 = "This is my first message, but it will arrive second (2).";
            var message2 = "Was there some message missing Bob? It will be delivered after this.";
            var message3 = "This is my second message, but it will arrive first (2).";
            axolotl.sendMessage(stateBob, message1, function(err, ciphertext1, state) {
                expect(err, 'Error from Bob sending 1st message').to.not.exist;
                stateBob = state;
                axolotl.sendMessage(stateBob, message3, function(err,ciphertext3,state){
                    expect(err, 'Error from Bob sending 2nd message').to.not.exist;
                    stateBob = state;
                    axolotl.recvMessage(stateAlice, ciphertext3, function(err, plaintext, state) {
                        expect(err, 'Error from Alice receiving 2nd message').to.not.exist;
                        myutil.debug("Plaintext:", plaintext);
                        expect(plaintext, '2nd message from Bob to Alice').to.equal(message3);
                        stateAlice = state;
                        axolotl.sendMessage(stateAlice, message2, function(err, ciphertext2, state) {
                            expect(err, 'Error from Alice sending message').to.not.exist;
                            stateAlice = state;
                            axolotl.recvMessage(stateAlice, ciphertext1, function(err, plaintext, state) {
                                expect(err, 'Error from Alice receiving 1st message').to.not.exist;
                                stateAlice = state;
                                myutil.debug("Plaintext:", plaintext);
                                expect(plaintext, '1st message from Bob to Alice').to.equal(message1);
                            });
                        });
                    });
                });
            });
            done();
        });
        /**
         * Delete AxolotlState.
         */
        after(function(done){
            stateBob.remove( function(){
            });
            done();
        });
    });
});

describe('Prekey storage and retrieval', function(){
    describe('Carol should be able to talk to Alice', function(){
        var stateAB, stateBA, stateCB, stateBC, stateAC, stateCA;
        var id_macs = {};
        var params = {};
        /**
         * Setup AxolotlStates for Alice<->Bob, Bob<->Carol via key agreement.
         */
        before(function(done) {
            /*##################################################
             * Alice
             *##################################################*/
            function updateStateAlice(keysAlice, keyExchangeMsgBob) {
                stateAB.root_key              = keysAlice.rk;
                stateAB.chain_key_recv        = keysAlice.ck; // Alice is Client. So we set CKr first.
                stateAB.header_key_recv       = keysAlice.hk;
                stateAB.next_header_key_send  = keysAlice.nhk0;    //FIXME: invert
                stateAB.next_header_key_recv  = keysAlice.nhk1;    // -"-
                stateAB.dh_identity_key_send  = nacl.to_hex(params.alice.id.boxSk);
                stateAB.dh_identity_key_recv  = nacl.to_hex(keyExchangeMsgBob.id);
                stateAB.dh_ratchet_key_recv   = nacl.to_hex(keyExchangeMsgBob.eph1);   // Storing secret (private) key here. Should we store the whole key pair instead?
                stateAB.counter_send = 0;
                stateAB.counter_recv = 0;
                stateAB.previous_counter_send = 0;
                stateAB.ratchet_flag = true;
            }
            token.create_id(function(alice_id_token) {
                params.alice = axolotl.genParametersAlice();
                id_macs.alice = alice_id_token.mac;
                var aliceKeyExchangeMsg = {    // extract public keys
                    'id_mac': alice_id_token.mac,
                    'id'    : nacl.to_hex(params.alice['id']['boxPk']),
                    'eph0'  : nacl.to_hex(params.alice['eph0']['boxPk'])
                };
                axolotl.keyAgreement(aliceKeyExchangeMsg,
                    function(err, ourKeyExchangeMsg, keys, state){
                        if (err) {
                            myutil.log(err);
                            myutil.log('Bob reports an error when trying to perform a key agreement.');
                        } else {
                            stateBA = state;
                            axolotl.keyAgreementAlice(params.alice, ourKeyExchangeMsg, function(err, keys) {
                                if (err) {        
                                    myutil.log(err);
                                    throw new Error('Apparently Alice could not finish the key agreement.');
                                } else {
                                    stateAB = new AxolotlState();
                                    stateAB.id_mac = 'BobID';
                                    updateStateAlice(keys, ourKeyExchangeMsg);
                                }
                            });
                        }
                });
            });
            /*##################################################
             * Carol
             *##################################################*/
            function updateStateCarol(keysCarol, keyExchangeMsgBob) {
                stateCB.root_key              = keysCarol.rk;
                stateCB.chain_key_recv        = keysCarol.ck;
                stateCB.header_key_recv       = keysCarol.hk;
                stateCB.next_header_key_send  = keysCarol.nhk0;
                stateCB.next_header_key_recv  = keysCarol.nhk1;
                stateCB.dh_identity_key_send  = nacl.to_hex(params.carol.id.boxSk);
                stateCB.dh_identity_key_recv  = nacl.to_hex(keyExchangeMsgBob.id);
                stateCB.dh_ratchet_key_recv   = nacl.to_hex(keyExchangeMsgBob.eph1);
                stateCB.counter_send = 0;
                stateCB.counter_recv = 0;
                stateCB.previous_counter_send = 0;
                stateCB.ratchet_flag = true;
            }
            token.create_id(function(carol_id_token) {
                params.carol = axolotl.genParametersAlice(); //Well.. misnamed that one...
                id_macs.carol = carol_id_token.mac;
                var carolKeyExchangeMsg = {    // extract public keys
                    'id_mac': carol_id_token.mac,
                    'id'    : nacl.to_hex(params.carol['id']['boxPk']),
                    'eph0'  : nacl.to_hex(params.carol['eph0']['boxPk'])
                };
                axolotl.keyAgreement(carolKeyExchangeMsg,
                    function(err, ourKeyExchangeMsg, keys, state){
                        if (err) {
                            myutil.log(err);
                            myutil.log('Bob reports an error when trying to perform a key agreement.');
                        } else {
                            stateBC = state;
                            axolotl.keyAgreementAlice(params.carol, ourKeyExchangeMsg, function(err, keys) { // also misnamed
                                if (err) {        
                                    myutil.log(err);
                                    throw new Error('Apparently Alice could not finish the key agreement.');
                                } else {
                                    stateCB = new AxolotlState();
                                    stateCB.id_mac = 'BobID';
                                    updateStateCarol(keys, ourKeyExchangeMsg);
                                }
                            });
                        }
                });
            });
            done();
        });

        it('Alice should be able to deposit her prekeys with Bob', function(done){
            params.alice.prekeys = [];
            var localPrekey = nacl.crypto_box_keypair();
            params.alice.prekeys.push({ 'id': 1, 'key' : localPrekey });
            var message = JSON.stringify({ 'id_mac' : id_macs.alice, 
                'key_id' : 1, 
                'base_key' : nacl.to_hex(localPrekey.boxPk) });
            var message2 = "giefprekey";
            axolotl.sendMessage(stateAB, message, function(err, ciphertext, state) {
                expect(err, 'Error from Alice sending prekey').to.not.exist;
                stateAB = state;
                axolotl.recvMessage(stateBA, ciphertext, function(err, plaintext, state){
                    expect(err, 'Error from Bob receiving prekey').to.not.exist;
                    stateBA = state;
                    myutil.debug('Plaintext:', plaintext);
                    expect(plaintext, 'prekey message from Alice').to.equal(message);
                    var pk = JSON.parse(plaintext);
                    prekey.put(id_macs.alice, pk.key_id, pk.base_key, function(err){
                        expect(err, 'Error from Bob saving prekey').to.not.exist;
                        axolotl.sendMessage(stateCB, message2, function(err, ciphertext, state) {
                            expect(err, 'Error from Carol requesting prekey').to.not.exist;
                            stateCB = state;
                            axolotl.recvMessage(stateBC, ciphertext, function(err, plaintext, state) {
                                expect(err, 'Error from Bob receiving prekey request').to.not.exist;
                                stateBC = state;
                                prekey.get(id_macs.alice, function(err, found){
                                    expect(err, 'Error from Bob retrieving prekey').to.not.exist;
                                    var answer = JSON.stringify({
                                        'key_id' : found.key_id,
                                        'base_key' : found.base_key
                                    });
                                    axolotl.sendMessage(stateBC, answer, function(err, ct, state) {
                                        expect(err, 'Error delivering prekey').to.not.exist;
                                        stateBC = state;
                                        axolotl.recvMessage(stateCB, ct, function(err, pt, state) {
                                            expect(err, 'Error from Carol receiving prekey').to.not.exist;
                                            stateCB = state;
                                            var alices_pk = JSON.parse(pt);
                                            //prekeyExchange(alices_pk, function() {
                                            // TODO: send message with prekey
                                            // This means creating a new state by performing
                                            // a somewhat local key exchange...
                                            // Can any of the already known functions be used?
                                            // This will quite the amount of work and code
                                            // will likely not be reused as this logic
                                            // will eventually be client-side.
                                            // That's enough reason for me to postpone this
                                            // right now.
                                            //});
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
            done();
        });

        after(function(done){
            AxolotlState.remove({ _id : stateBA._id }, function(){
            });
            AxolotlState.remove({ _id : stateBC._id }, function(){
            });
            done();
        });
    });
});

// To get an AxolotlState: AxolotlState.findOne({id_mac: from}).exec().onFulfill(function(result){
