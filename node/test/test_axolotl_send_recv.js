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
 * Setup AxolotlStates for Alice and Bob via key agreement.
 */
function performKeyExchange(callback) {
    var stateAlice;
    function updateStateAlice(keysAlice, keyExchangeMsgBob) {
        stateAlice.root_key              = keysAlice.rk;
        stateAlice.chain_key_recv        = keysAlice.ck; // Alice is Client. So we set CKr first.
        stateAlice.header_key_recv       = keysAlice.hk;
        stateAlice.next_header_key_send  = keysAlice.nhk0;    //FIXME: invert
        stateAlice.next_header_key_recv  = keysAlice.nhk1;    // -"-
        stateAlice.dh_identity_key_send  = aliceParams.id.secretKey;
        stateAlice.dh_identity_key_send_pub  = aliceParams.id.publicKey;
        stateAlice.dh_identity_key_recv  = new Buffer(keyExchangeMsgBob.id, 'base64');
        stateAlice.dh_ratchet_key_recv   = new Buffer(keyExchangeMsgBob.eph1, 'base64');   // Storing secret (private) key here. Should we store the whole key pair instead?

        stateAlice.counter_send = 0;
        stateAlice.counter_recv = 0;
        stateAlice.previous_counter_send = 0;
        stateAlice.ratchet_flag = true;
        // Alice's state is not a data source, so we need to save this by hand.
        stateAlice.save(function (err, state) {
            expect(err).to.not.exist;
            callback(aliceParams.id.publicKey, keyExchangeMsgBob.id);
        });
    }
    var aliceParams = axolotl.genParametersAlice();
    var aliceKeyExchangeMsg = {    // extract public keys
        'id'    : aliceParams['id']['publicKey'].toString('base64'),
        'eph0'  : aliceParams['eph0']['publicKey'].toString('base64')
    };
    axolotl.keyAgreement(aliceKeyExchangeMsg, function(err, ourKeyExchangeMsg){
        if (err) {
            myutil.log('Bob reports an error when trying to perform a key agreement.\n\t' + err.message);
            throw err;
        } else {
            axolotl.keyAgreementAlice(aliceParams, ourKeyExchangeMsg, function(err, keys) {
                if (err) {        
                    myutil.log(err);
                    throw new Error('Apparently Alice could not finish the key agreement.');
                } else {
                    stateAlice = new AxolotlState();
                    updateStateAlice(keys, ourKeyExchangeMsg);
                }
            });
        }
    });
}
/**
 * Tests for sending and receiving messages.
 */
describe('Message sending and receiving', function(){
    /**
     * Test the sendMessage() function (server) vs the recvMessage() function (client).
     * Valid AxolotlStates need to be set up before.
     */
    describe('Sending messages (no ratchet). (->)', function(){
        var toAlice, fromAlice;
        var toBob, fromBob;
        before(function(done){
            performKeyExchange(function(aliceID, bobID) {
                toAlice = fromAlice = aliceID;
                toBob = fromBob = bobID;
                done();
            });
        });

        it('multiple messages to the client should be decryptable (no ratchet)', function(done) {
            var message = "Hello World. I am a MobileEdge Axolotl test message and I am sent repeatedly.";
            var message2 = "Hello World. I am a MobileEdge Axolotl test message and I am sent repeatedly (2).";
            axolotl.sendMessage(toAlice, message, function(err, ciphertext) {
                expect(err, 'Error from Bob sending message (2)').to.not.exist;
                axolotl.recvMessage(fromBob, ciphertext, function(err, plaintext) {
                    expect(err, 'Error from Alice receiving message (2).').to.not.exist;
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message);
                    axolotl.sendMessage(toAlice, message2, function(err, ciphertext) {
                        expect(err, 'Error from Bob sending next message (3).').to.not.exist;
                        axolotl.recvMessage(fromBob, ciphertext, function(err, plaintext) {
                            expect(err, 'Error from Alice receiving message (3).').to.not.exist;
                            expect(plaintext).to.equal(message2);
                            done();
                        });
                    });
                });
            });
        });

        after(function () {
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromAlice, 'base64') }, function(){});
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromBob, 'base64') }, function(){});
        });
    });
    /**
     * Test the recvMessage() function (server) vs the sendMessage() function (client).
     * Valid AxolotlStates need to be set up before. 
     * Additionally one message must be sent from the server to the client first, to complete
     * the first ratchet.
     */
    describe('Receiving messages (no ratchet). (<-)', function(){
        var toAlice, fromAlice;
        var toBob, fromBob;
        before(function(done){
            performKeyExchange(function(aliceID, bobID) {
                toAlice = fromAlice = aliceID;
                toBob = fromBob = bobID;
                done();
            });
        });
        
        it('multiple messages from the client should be decryptable (no ratchet)', function(done) {
            var message1 = "(<-) Hello, I am the first message from client to server!";
            var message2 = "(<-) Hello, I am the second message from client to server!";
            var message3 = "(<-) Hello, I am the third message from client to server!";
            axolotl.sendMessage(toBob, message1, function(err, ciphertext) {
                expect(err, '(<-) Error from Alice sending 1st message').to.not.exist;
                axolotl.recvMessage(fromAlice, ciphertext, function(err, plaintext) {
                    expect(err, '(<-) Error from Bob receiving message').to.not.exist;
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message1);
                    axolotl.sendMessage(toBob, message2, function(err, ciphertext) {
                        expect(err, '(<-) Error from Alice sending 2nd message').to.not.exist;
                        axolotl.recvMessage(fromAlice, ciphertext, function(err, plaintext) {
                            expect(err, '(<-) Error from Bob receiving message').to.not.exist;
                            expect(plaintext, 'decrypted plaintext == message').to.equal(message2);
                            axolotl.sendMessage(toBob, message3, function(err, ciphertext) {
                                expect(err, '(<-) Error from Alice sending 3rd message').to.not.exist;
                                axolotl.recvMessage(fromAlice, ciphertext, function(err, plaintext) {
                                    expect(err, '(<-) Error from Bob receiving message').to.not.exist;
                                    expect(plaintext, 'decrypted plaintext == message').to.equal(message3);
                                    done();
                                });
                            });
                        });
                    });
                });
            });
        });

        after(function () {
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromAlice, 'base64') }, function(){});
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromBob, 'base64') }, function(){});
        });
    });
    describe('Interleaved messages (<->)', function(){
        var toAlice, fromAlice;
        var toBob, fromBob;
        before(function(done){
            performKeyExchange(function(aliceID, bobID) {
                toAlice = fromAlice = aliceID;
                toBob = fromBob = bobID;
                done();
            });
        });
        
        it('sending and receiving interleaved: messages are decryptable', function(done) {
            var message1 = "First message (Alice to Bob).";
            var message2 = "Second message (Bob to Alice).";
            var message3 = "Third message (Alice to Bob).";
            var message4 = "Fourth message (Bob to Alice).";
            axolotl.sendMessage(toBob, message1, function(err, ciphertext) {
                expect(err, '(<->) Error from Alice sending 1st message').to.not.exist;
                axolotl.recvMessage(fromAlice, ciphertext, function(err, plaintext) {
                    expect(err, '(<->) Error from Bob receiving 1st message').to.not.exist;
                    expect(plaintext, 'decrypted plaintext == message').to.equal(message1);
                    axolotl.sendMessage(toAlice, message2, function(err, ciphertext) {
                        expect(err, '(<->) Error from Bob sending 2nd message').to.not.exist;
                        axolotl.recvMessage(fromBob, ciphertext, function(err, plaintext) {
                            expect(err, '(<->) Error from Alice receiving 2nd message').to.not.exist;
                            expect(plaintext, 'decrypted plaintext == message').to.equal(message2);
                            axolotl.sendMessage(toBob, message3, function(err, ciphertext) {
                                expect(err, '(<->) Error from Alice sending 3rd message').to.not.exist;
                                axolotl.recvMessage(fromAlice, ciphertext, function(err, plaintext) {
                                    expect(err, '(<->) Error from Bob receiving 3rd message').to.not.exist;
                                    expect(plaintext, 'decrypted plaintext == message').to.equal(message3);
                                    axolotl.sendMessage(toAlice, message4, function(err, ciphertext) {
                                        expect(err, '(<->) Error from Bob sending 4th message').to.not.exist;
                                        axolotl.recvMessage(fromBob, ciphertext, function(err, plaintext) {
                                            expect(err, '(<->) Error from Bob receiving message').to.not.exist;
                                            expect(plaintext, 'decrypted plaintext == message').to.equal(message4);
                                            done();
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });

        after(function () {
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromAlice, 'base64') }, function(){});
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromBob, 'base64') }, function(){});
        });
    });

    describe('Skipped messages while sending (no ratchet). (~>)', function(){
        var toAlice, fromAlice;
        var toBob, fromBob;
        before(function(done){
            performKeyExchange(function(aliceID, bobID) {
                toAlice = fromAlice = aliceID;
                toBob = fromBob = bobID;
                done();
            });
        });
        
        it('skipped messages should be decrypted fine', function(done){
            var message1 = "This is my first message, but it will arrive second.";
            var message2 = "This is my second message, but it will arrive first.";
            axolotl.sendMessage(toAlice, message1, function(err, ciphertext1) {
                expect(err, '(~>) Error from Bob sending 1st message').to.not.exist;
                axolotl.sendMessage(toAlice, message2, function(err,ciphertext2){
                    expect(err, '(~>) Error from Bob sending 2nd message').to.not.exist;
                    axolotl.recvMessage(fromBob, ciphertext2, function(err, plaintext) {
                        expect(err, '(~>) Error from Alice receiving 2nd message').to.not.exist;
                        expect(plaintext, 'decrypted plaintext == message').to.equal(message2);
                        axolotl.recvMessage(fromBob, ciphertext1, function(err, plaintext) {
                            expect(err, '(~>) Error from Alice receiving 1st message').to.not.exist;
                            expect(plaintext, 'decrypted plaintext == message').to.equal(message1);
                            done();
                        });
                    });
                });
            });
        });

        after(function () {
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromAlice, 'base64') }, function(){});
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromBob, 'base64') }, function(){});
        });
    });

    describe('Skipped messages while receiving (no ratchet). (<~)', function(){
        var toAlice, fromAlice;
        var toBob, fromBob;
        before(function(done){
            performKeyExchange(function(aliceID, bobID) {
                toAlice = fromAlice = aliceID;
                toBob = fromBob = bobID;
                done();
            });
        });
        
        it('skipped messages should be decrypted fine', function(done){
            var message1 = "This is my first message, but it will arrive second.";
            var message2 = "This is my second message, but it will arrive first.";
            axolotl.sendMessage(toBob, message1, function(err, ciphertext1) {
                expect(err, '(<~) Error from Alice sending 1st message').to.not.exist;
                axolotl.sendMessage(toBob, message2, function(err,ciphertext2){
                    expect(err, '(<~) Error from Alice sending 2nd message').to.not.exist;
                    axolotl.recvMessage(fromAlice, ciphertext2, function(err, plaintext) {
                        expect(err, '(<~) Error from Bob receiving 2nd message').to.not.exist;
                        expect(plaintext, 'decrypted plaintext == message').to.equal(message2);
                        axolotl.recvMessage(fromAlice, ciphertext1, function(err, plaintext) {
                            expect(err, '(<~) Error from Bob receiving 1st message').to.not.exist;
                            expect(plaintext, 'decrypted plaintext == message').to.equal(message1);
                            done();
                        });
                    });
                });
            });
        });

        after(function () {
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromAlice, 'base64') }, function(){});
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromBob, 'base64') }, function(){});
        });
    });

    describe('Skipped messages (ratchet). (<~>)', function(){
        var toAlice, fromAlice;
        var toBob, fromBob;
        before(function(done){
            performKeyExchange(function(aliceID, bobID) {
                toAlice = fromAlice = aliceID;
                toBob = fromBob = bobID;
                done();
            });
        });
        
        it('skipped messages with ratchet in between should be decrypted fine', function(done){
            var message1 = "This is my first message, but it will arrive second.";
            var message2 = "Was there some message missing, Bob? It will be delivered after this.";
            var message3 = "This is my second message, but it will arrive first.";
            axolotl.sendMessage(toAlice, message1, function(err, ciphertext1) {
                expect(err, '(<~>) Error from Bob sending 1st message').to.not.exist;
                axolotl.sendMessage(toAlice, message3, function(err,ciphertext3){
                    expect(err, '(<~>) Error from Bob sending 2nd message').to.not.exist;
                    axolotl.recvMessage(fromBob, ciphertext3, function(err, plaintext) {
                        expect(err, '(<~>) Error from Alice receiving 2nd message').to.not.exist;
                        expect(plaintext, 'decrypted plaintext == message').to.equal(message3);
                        axolotl.sendMessage(toBob, message2, function(err, ciphertext2) {
                            expect(err, '(<~>) Error from Alice sending message').to.not.exist;
                            axolotl.recvMessage(fromAlice, ciphertext2, function(err, plaintext){
                                expect(err, '(<~>) Error from Bob receiving 2nd message').to.not.exist;
                                expect(plaintext, 'decrypted plaintext == message').to.equal(message2);
                                axolotl.recvMessage(fromBob, ciphertext1, function(err, plaintext) {
                                    expect(err, '(<~>) Error from Alice receiving 1st message').to.not.exist;
                                    expect(plaintext, 'decrypted plaintext == message').to.equal(message1);
                                    done();
                                });
                            });
                        });
                    });
                });
            });
        });

        after(function () {
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromAlice, 'base64') }, function(){});
            AxolotlState.remove({ dh_identity_key_recv : new Buffer(fromBob, 'base64') }, function(){});
        });
    });
});
