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
 * @module axolotl
 * @description Axolotl key agreement and ratcheting as described in
 *  {@link https://github.com/trevp/axolotl/wiki}.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */


var mongoose = require('mongoose'),
    fs = require('fs'),
    sodium = require('sodium').api,
    mu = require('./util.js'),
    cu = require('./crypto_util.js'),
    schema = require('../models/schema.js'),
    ds = require('../models/DataSourceMongoose.js');

var DataSource = ds.DataSource;
var Identity = mongoose.model('Identity'),
    AxolotlState = mongoose.model('AxolotlState');

/**
 * @description Declare a more meaningful name for crypto_box_keypair in this context.
 * @function newDHParam
 * @static
 */
var newDHParam = sodium.crypto_box_keypair;

/**
 * @description (Synchronously) get the Axolotl ID key from a file. This is
 * needed for the key exchange.
 * 
 * @return {Object} the ID key as an object containing two Uint8Arrays.
 */
var getIDKey = function() {
    var str = fs.readFileSync('./private_ec_id', {encoding: 'utf8'});
    var buf = new Buffer(str, 'base64');
    var id = JSON.parse(buf.toString('utf8'));
    id.secretKey = new Buffer(id.boxSk, 'hex');
    id.publicKey = new Buffer(id.boxPk, 'hex');
    return id;
};

/**
 * @description 
 * Generate (and print) a new (permanent) ID key for use in the Axolotl ratchet protocol.
 * Prints the Base64-encoded JSON of the object that is returned.
 *
 * This function is likely not used in production and may be moved to a different place
 * soon.
 * 
 * @return {Object} An object containing secretKey and publicKey, both as hex string.
 */
var generateIDKey = function() {
    var params = newDHParam();
    params.secretKey = params.secretKey.toString('base64');
    params.publicKey = params.publicKey.toString('base64');
    mu.debug('Buff:', (new Buffer(JSON.stringify(params))).toString('base64'));
    return params;
};

/**
 * @description Key derivation wrapper just for Bob.
 * 
 * @param {Object} mine Bob's key exchange message
 * @param {Object} their Alice's key exchange message
 * @param {Function} callback function to call when done
 */
var deriveKeysBob = exports.deriveKeysBob =
function deriveKeysBob(mine, their, callback) {
    mu.debug('deriveKeysBob', mine.id, their.eph0);
    var part1 = sodium.crypto_scalarmult(mine.eph0.secretKey, new Buffer(their.id, 'base64')),
        part2 = sodium.crypto_scalarmult(mine.id.secretKey, new Buffer(their.eph0, 'base64')),
        part3 = sodium.crypto_scalarmult(mine.eph0.secretKey, new Buffer(their.eph0, 'base64'));
    deriveKeys(part1, part2, part3, callback)
}

/**
 * @description Key derivation wrapper just for Alice.
 * 
 * @param {Object} mine Alice's key exchange message
 * @param {Object} their Bob's key exchange message
 * @param {Function} callback function to call when done
 */
var deriveKeysAlice = exports.deriveKeysAlice =
function deriveKeysAlice(mine, their, callback) {
    mu.debug('deriveKeysAlice', mine.id, their.id);
    var part1 = sodium.crypto_scalarmult(mine.id.secretKey, new Buffer(their.eph0, 'base64')),
        part2 = sodium.crypto_scalarmult(mine.eph0.secretKey, new Buffer(their.id, 'base64')),
        part3 = sodium.crypto_scalarmult(mine.eph0.secretKey, new Buffer(their.eph0, 'base64'));
    deriveKeys(part1, part2, part3, callback)
}

/**
 * @description Key derivation wrapper common to Alice and Bob.
 * 
 * @param {Buffer} part1 first part of the input material
 * @param {Buffer} part2 second part of the input material
 * @param {Buffer} part3 third part of the input material
 * @param {Function} callback function to call when done
 */
function deriveKeys(part1, part2, part3, callback) {
    var master_key = sodium.crypto_hash(
            Buffer.concat([part1, part2, part3], 3 * sodium.crypto_scalarmult_BYTES)
            ); // Note that this is SHA512 and not SHA256. It does not have to be.
    cu.hkdf(master_key, 'MobileEdge', 5*32, function(key){
        res = {
            'rk'    : key.slice(0, key.length / 5),
            'hk'   : key.slice(key.length / 5, 2 * key.length / 5),
            'nhk0'   : key.slice(2 * key.length / 5, 3 * key.length / 5),
            'nhk1'  : key.slice(3 * key.length / 5, 4 * key.length / 5),
            'ck'  : key.slice(4 * key.length / 5)
        };
        callback(res);
    });
}

/**
 * @description Performs the key agreement according to the axolotl protocol.
 *  Alice (the client) will initiate this key exchange, so her
 *  keyExchangeMsg will be present.
 *  The new AxolotlState object is created and saved to the database.
 *
 * @param {Object} keyExchangeMsg the object containing Alice's public identity
 *  key A, as well as her public ECDH parameter A0.
 * @param {Function} callback the function to be called when all keys are derived.
 *  Takes an error parameter and the keyExchangeMsg to be sent to Alice,
 *  containing our public identity key B as well as our public ECDH 
 *  parameters B0, B1, as well as the resulting shared secret. Takes as additional parameter the new state (AxolotlState)
 *  object, which the application should save to persistent memory.
 */
exports.keyAgreement = 
function keyAgreement(keyExchangeMsg, callback) {
    var dsm = new DataSource(),
        state = dsm.axolotl_state.create();
    var myId = getIDKey(),                  // B
        myEph0 = newDHParam(),       // B_0
        myEph1 = newDHParam();       // B_1
    var theirId = keyExchangeMsg['id'].toString('hex'), // A
        theirEph0 = keyExchangeMsg['eph0'].toString('hex'),                   // A_0
        theirEph1 = null;                   // A_1 (unused, remove?)
    // Axolotl generates master_key = H (DH(A,B_0) || DH(A_0,B) || DH(A_0,B_0))
    deriveKeysBob({ 'id': myId, 'eph0' : myEph0, 'eph1' : myEph1 },
                keyExchangeMsg,
                function(res) {
        state.root_key              = res.rk;
        state.chain_key_send        = res.ck; // Server is Bob. So we set CKs first.
        state.header_key_send       = res.hk;
        state.next_header_key_recv  = res.nhk0;
        state.next_header_key_send  = res.nhk1;
        state.dh_identity_key_send_pub  = myId.publicKey;
        state.dh_identity_key_send  = myId.secretKey;
        state.dh_identity_key_recv  = new Buffer(theirId,'base64');
        state.dh_ratchet_key_send   = myEph1.secretKey;   // Storing secret (private) key here. Should we store the whole key pair instead?
        state.dh_ratchet_key_send_pub = myEph1.publicKey;
        state.counter_send = 0;
        state.counter_recv = 0;
        state.previous_counter_send = 0;
        state.ratchet_flag = false;
        dsm.axolotl_state.save(function(err, doc) {
            if (err) {
                mu.log(err);
                callback(err);
            } else {
                callback(null, {
                    'id': myId.publicKey.toString('base64'),
                    'eph0' : myEph0.publicKey.toString('base64'),
                    'eph1': myEph1.publicKey.toString('base64')
                }, res, state);
            }
        });
    });
}

/**
 * @description Convenience function to generate a set of (2 public and private) 
 *  parameters for Alice. 
 *
 * @return {{id: NaClBoxKeyPair, eph0: NaClBoxKeyPair}} A new object containing 
 *  Alices identity key pair and an ephemeral ECDH key pair for the key exchange.
 *  The objects each contain a secretKey and a publicKey field.
 */
exports.genParametersAlice =
function genParametersAlice() {
    return {
        'id'    : newDHParam(),
        'eph0'  : newDHParam()
    };
}

/**
 * @description For testing purposes, we also need to emulate Alice (the client).
 */
exports.keyAgreementAlice =
function keyAgreementAlice(myParams, keyExchangeMsg, callback) {
    var myId = myParams.id,            // A
        myEph0 = myParams.eph0;       // A_0
    mu.debug('keyAgreementAlice', keyExchangeMsg);
    var theirId = keyExchangeMsg['id'],                     // B
        theirEph0 = keyExchangeMsg['eph0'],             // B_0
        theirEph1 = keyExchangeMsg['eph1'];                 // B_1 
    // Axolotl generates master_key = H (DH(A,B_0) || DH(A_0,B) || DH(A_0,B_0))
    deriveKeysAlice({ 'id': myId, 'eph0' : myEph0 },
                { 'id': theirId, 'eph0' : theirEph0, 'eph1' : theirEph1 }, 
                function(res) {
        callback(null, res);
    });
}

/**
 * @description Advance the ratchet state with the given client when sending a message.
 * @param {AxolotlState} state the AxolotlState associated with the receiver
 * @param {Function} callback the function to call when ratcheting is done.
 */
function advanceRatchetSend(state, callback) {
    var updatedKey = newDHParam();
    state.dh_ratchet_key_send = updatedKey.secretKey;
    state.dh_ratchet_key_send_pub = updatedKey.publicKey;
    state.header_key_send = state.next_header_key_send;
    var dh = sodium.crypto_scalarmult(
                state.dh_ratchet_key_send,
                state.dh_ratchet_key_recv),
        input = cu.hmac(state.root_key, dh)
    cu.hkdf(input, 'MobileEdge Ratchet', 3*32, function (key) {
        state.root_key = key.slice(0, key.length / 3);
        state.next_header_key_send = key.slice(key.length / 3, 2 * key.length / 3);
        state.chain_key_send = key.slice(2 * (key.length / 3));
        
        state.previous_counter_send = state.counter_send;
        state.counter_send = 0;
        state.ratchet_flag = false;
        callback(state);
    });
}

/** 
 * @callback EncryptionCallback 
 * @param {?Error} err the error if an error occurred
 * @param {?CiphertextMessage} ciphertext the encrypted message if encryption was
 *  successful
 */
/** 
 * @typedef CiphertextMessage
 * @type Object
 * @property {String} nonce the nonce used for encryption
 * @property {String} head the encrypted header
 * @property {String} body the encrypted body
 */

/**
 * @description Takes a message and encrypts it to the receiver, advancing the Axolotl
 * ratchet.
 * @param {string} identity - the public key (base64) associated with the recipient of the message.
 * @param {string} msg - the message (utf8) to be encrypted and sent
 * @param {EncryptionCallback} callback - the function to be called once the msg is safely encrypted
 *  Takes an error parameter (if, for instance, encryption is not possible) and
 *  the ciphertext, as well as the new state (AxolotlState) the application
 *  is responsible of saving to persistent storage.
 */
exports.sendMessage =
function sendMessage(identity, msg, callback) {
    //TODO: nonce in encrypted message
    var dsrc;
    function workerSend(state) {
        var msgKey = cu.hmac(state.chain_key_send, "0"),
            nonce1 = new Buffer(sodium.crypto_secretbox_NONCEBYTES),
            nonce2 = new Buffer(sodium.crypto_secretbox_NONCEBYTES);
        sodium.randombytes(nonce1);
        sodium.randombytes(nonce2);
        var msgBody = sodium.crypto_secretbox(
                        new Buffer(msg, 'utf8'),
                        nonce1,
                        new Buffer(msgKey)),
            msgHead = sodium.crypto_secretbox( //TODO: real concatenation of to 32bit ints here!
                        new Buffer(
                            JSON.stringify([state.counter_send,
                                state.previous_counter_send,
                                state.dh_ratchet_key_send_pub.toString('base64')])),
                        nonce2,
                        state.header_key_send);
        //Append the nonce to the end of ciphertext:
        msgBody = Buffer.concat([msgBody.slice(16), nonce1], 
                    msgBody.length - 16 + nonce1.length);
        msgHead = Buffer.concat([msgHead.slice(16), nonce2], 
                    msgHead.length - 16 + nonce2.length);
        var ciphertext = {
            'head'  : msgHead.toString('base64'),
            'body'  : msgBody.toString('base64')
                //TODO mac!?
        }
        mu.debug('in SEND:', ciphertext);
        state.counter_send += 1;
        state.chain_key_send = new Buffer(cu.hmac(state.chain_key_send, "1"));
        dsrc.axolotl_state.save(function(err, doc){
            if (err) {
                mu.log("ERROR in sendMessage:", err);
                callback(err, ciphertext, state);
            } else {
                callback(null, ciphertext, state);
            }
        });
    }
    dsrc = new DataSource();
    var kk = dsrc.axolotl_state;
    dsrc.axolotl_state.get(new Buffer(identity, 'base64'), function(err, state){
        if (!state) {
            mu.debug("Error:", "No state for this client present. Could not even fetch it myself.\nID:", identity);
            if (err)
                mu.log('Error from db:', err);
            callback(new Error("No state for this client present."));
        } else if (state.ratchet_flag) {
            advanceRatchetSend(state, workerSend);
        } else {
            workerSend(state);
        }
    }); 
}

/* ############################################################################
 * Everything below here is message reception. This includes the helper
 * functions described in the Axolotl protocol description at 
 * https://github.com/trevp/axolotl/wiki but also some convenient other helper
 * functions.
 *
 * ##########################################################################*/

/**
 * @description Advance the ratchet state with the given client when receiving a message.
 *
 * @param {AxolotlState} state the state with a given client
 * @param {Buffer} purportedRootKey the purported new root key to be written to the state
 * @param {Buffer} purportedHeaderKey the purported new header key to be written to the state
 * @param {Buffer} purportedNextHeaderKey the purported new next header key to be 
 *  written to the state
 * @param {String} purportedDHRatchetKey the purported DH ratchet key to be written to the state.
 *  Given as a base64 string. needs to be converted!
 * @return {AxolotlState} the new state.
 */
function advanceRatchetRecv(state, purportedRootKey, purportedHeaderKey, 
        purportedNextHeaderKey, purportedDHRatchetKey) {

    mu.debug("state in advRatRecv: ",state);
    state.root_key = purportedRootKey;
    state.header_key_recv = purportedHeaderKey;
    state.next_header_key_recv = purportedNextHeaderKey;
    state.dh_ratchet_key_recv = new Buffer(purportedDHRatchetKey, 'base64');
    state.dh_ratchet_key_send = null;
    state.dh_ratchet_key_send_pub = null;
    state.ratchet_flag = true;
    mu.debug("state AFTER advRatRecv: ",state);
    return state;
}

/**
 * @description Function that tries to decrypt the current message with skipped
 *  header and message keys that were saved to persistent storage before.
 *
 * @param {AxolotlState} state the state for a given client.
 * @param {Object} msg the ciphertext message object.
 * @return {Object|Error} either an error or an object containing the new state
 *  (delete skipped keys that succeeded in decrypting) and the plaintext if
 *  decryption was possible.
 */
function try_skipped_header_and_message_keys(state, msg) {
    for (var i = 0; i < state.skipped_hk_mk.length; i++) {
        mu.debug("try_skipped: key:", state.skipped_hk_mk[i].hk);
        var purportedHdr = decryptHeader(state.skipped_hk_mk[i].hk, msg.head);
        if (purportedHdr instanceof Error) { // this skipped header key was not the right one
            continue;
        }
        var plainMsg = decryptBody(state.skipped_hk_mk[i].mk, msg.body);
        if (plainMsg instanceof Error) { // this message key was not the right one
            continue;
        }
        state.skipped_hk_mk.splice(i,1);// delete skipped keys, FIXME: does this do what I think it does?
        return { 'state' : state, 'msg' : plainMsg }
    }
    return new Error('Unable to decrypt using skipped keys.');
}

/**
 * @description Given a header key, a (possibly past) message counter Nr, a purported
 *  new message count (Np), and a chain key, this function calculates all the message keys
 *  for messages with Nr < N <= Np and saves everything but the last one to a staging
 *  area (associating it with the header key).
 *
 * @param {Array} stagingArea - the staging area to save the keys to
 * @param {Buffer} HKr the header key for reception
 * @param {Number} Nr the "old" message counter
 * @param {Number} Np purported "new" message counter
 * @param {Buffer} CKr the (reception) chain key
 * @return {Object} an object containing the last computed chain key, message key, and
 *  the possibly populated staging area.
 */
function stage_skipped_header_and_message_keys(stagingArea, HKr, Nr, Np, CKr, stage_result) {
    var msgKey,
        headerKey = HKr,
        chainKey = CKr;
    mu.debug('stage_skipped: key:', headerKey);
    for (var i = Nr; i < Np; i++) {
        // Each message will have a different MK derived from the chain key.
        msgKey = cu.hmac(chainKey, "0");
        // The chain key will also be derived and renewed in each step.
        chainKey = cu.hmac(chainKey, "1");
        stagingArea.push({
            'timestamp' : Date.now(),    //might be unnecessary.
            'hk' : headerKey,
            'mk': new Buffer(msgKey)
        });
    }
    // One last step for the last message key. This one will not be
    // added to the staging area, as it can be used to decrypt the current message.
    // FIXME: Should it be staged and kept in some cases?
    msgKey = cu.hmac(chainKey, "0");
    chainKey = cu.hmac(chainKey, "1");
    
    if (stage_result && Nr != Np) {
        stagingArea.push({
            'timestamp' : Date.now(),    //might be unnecessary.
            'hk' : headerKey,
            'mk': new Buffer(msgKey)
        });
    }
    return { 'CKp' : chainKey, 'MK' : msgKey, 'stagingArea' : stagingArea };
}

/**
 * @description Takes a state and a staging area and introduces skipped keys from the
 *  staging area into the state.
 *
 * @param {AxolotlState} state the Axolotl state
 * @param {Array} stagingArea the staging area populated with skipped keys
 * @return {AxolotlState} the modified state
 */
function commit_skipped_header_and_message_keys(state, stagingArea) {
    mu.debug("commit: ", state.skipped_hk_mk, stagingArea);
    state.skipped_hk_mk = state.skipped_hk_mk.concat(stagingArea);
    return state;
}

/**
 * @description Decrypts a header ciphertext with a given key and corresponding nonce.
 *
 * @param {Buffer} key - the header key
 * @param {String} ciphertext - the encrypted message header (base64)
 * @param {String} nonce - the corresponding nonce (base64)
 * @return {Error|Array} either an Error if decryption failed, or the Array object corresponding
 *  to the decrypted header.
 */
function decryptHeader(key, ciphertext) {
    //TODO: nonce in encrypted message
    var plainHdr;
    var buf = Buffer.concat([new Buffer(16).fill(0), new Buffer(ciphertext, 'base64')]);
    var nonce = buf.slice(-24);
    var paddedCiphertext = buf.slice(0,-24);

    mu.debug('key:', key, 'text:', ciphertext, 'nonce', nonce);
    try { //TODO: use domains instead, not try/catch?
        plainHdr = sodium.crypto_secretbox_open(
                paddedCiphertext,
                new Buffer(nonce, 'base64'), 
                key); //key was stored as Buffer or computed locally
        if (!plainHdr) return new Error('Header decryption failed!' +
               ciphertext + typeof(ciphertext));
    } catch (err) {
        return new Error('Header decryption failed' + err.message);
    }
    try {
        var header = JSON.parse(plainHdr.toString('utf8'));
        return header;
    } catch (err) {
        mu.log('Invalid header format!', err.message);
        return new Error('Invalid header format:' + err.message + plainHdr );
    }
}

/**
 * @description Decrypts a message body ciphertext, given a corresponding key and nonce.
 *
 * @param {Buffer} key - the message key
 * @param {String} ciphertext - the message ciphertext (base64)
 * @param {String} nonce - the corresponding nonce (base64)
 * @return {Error|String} either an Error if decryption failed, or a String containing 
 *  the decrypted message.
 */
function decryptBody(key, ciphertext) {
    //TODO: nonce in encrypted message
    var plaintext;
    var buf = Buffer.concat([new Buffer(16).fill(0), new Buffer(ciphertext, 'base64')]);
    var nonce = buf.slice(-24);
    var paddedCiphertext = buf.slice(0,-24);

    try { //TODO: use domains instead, not try/catch!
        plaintext = sodium.crypto_secretbox_open(
                paddedCiphertext,
                new Buffer(nonce, 'base64'),
                key);
        if (!plaintext) return new Error('Body decryption failed! ' +
               ciphertext + typeof(ciphertext));
    } catch (err) {
        return new Error(err.message);
    }
    return plaintext.toString('utf8');
}

/**
 * @description Finishes decryption and state update, independent of the method used to 
 * decrypt the message. Calls the recv functions callback for it.
 * @param {AxolotlState} state - the state
 * @param {String} plaintext - the plaintext of the message
 * @param {Number} Np - message counter to update the one in the state with
 * @param {Buffer} CKp - the new purported chain key to save to the state
 * @param {Function} callback - the callback to call with plaintext and updated state
 */
function finish(dsrc, stagingArea, plaintext, Np, CKp, callback) {
    var state = dsrc.axolotl_state.retrieve();
    state = commit_skipped_header_and_message_keys(state, stagingArea);
    state.counter_recv = Np + 1;
    state.chain_key_recv = CKp;

    dsrc.axolotl_state.save(function(err){
        if (err) {
            mu.log("ERROR in recvMessage saving state:", err);
            callback(err, plaintext, state);
        } else {
            callback(null, plaintext, state);
        }
    });
}

/**
 * @description Parse the header (array) into an object.
 *
 * @param {Array} header the header
 * @return {Object} the parsed header
 */
function parseHeader(header) {
    //TODO: nonce in encrypted message
    return {
        'msg_number'        : header[0],
        'prev_msg_number'   : header[1],
        'dh_ratchet_key'    : header[2]
    };
}

/**
 * @description Handle a potential error by logging a message and calling
 *  the callback with an error. If the given parameter is not an error,
 *  nothing happens.
 * 
 * @param err something that might be an Error
 * @param msg message to display if err was actually an Error
 * @param decryptionCallback callback the function to call in case we had an error.
 */
function handlePotentialError(err, msg, callback) {
    if (err instanceof Error) {
        mu.log(msg,'\n\t', err.message);
        callback(err);
    }
}

/**
 * @description handle the decryption of a message body when decryption of the
 *  header with an existing header key was successful. No ratchet is needed in
 *  this case. This corresponds to the times when we are repeatedly receiving
 *  messages from a client and not answering to advance the ratchet.
 *
 * @param {DataSource} dsrc - the data source for the AxolotlState
 * @param {AxolotlState} state - the state for the client
 * @param {CiphertextMessage} ciphertext - the encrypted message object
 * @param {Array} purportedHdr - the purported decrypted header of the message
 * @param {Array} stagingArea - the staging area for skipped keys
 * @param {DecryptionCallback} callback - the function to call with the decrypted message or an error
 */
function handleWithExistingKey(dsrc, state, ciphertext, purportedHdr, stagingArea, callback) {
    // ... and decryption with it does not fail.
    //TODO: nonce in encrypted message
    var hdr = parseHeader(purportedHdr);
    var keys = stage_skipped_header_and_message_keys(stagingArea, state.header_key_recv, 
            state.counter_recv, hdr.msg_number, state.chain_key_recv);
    var purportedChainKey = keys.CKp;
    var plaintext = decryptBody(keys.MK, ciphertext.body);
    if (plaintext instanceof Error) {
        mu.log('Error: Failed to decrypt message body with purported message key (1).',
        '\n\t', plaintext.message);
        callback(plaintext);
    } else {
        stagingArea = keys.stagingArea;
        finish(dsrc, stagingArea, plaintext, hdr.msg_number, purportedChainKey, callback);
    }
}

/**
 * @description Attempt to decrypt a message body, when new key material had to be
 *  derived and ratcheting is needed.
 *
 * @param {DataSource} dsrc - the data source for the AxolotlState
 * @param {AxolotlState} state - the state for the client
 * @param {CiphertextMessage} ciphertext - the encrypted message object
 * @param {Object} hdr - the parsed message header
 * @param {Buffer} key - the derived key material
 * @param {Buffer} purportedHeaderKey - the purported header key. Needed to update ratchet.
 * @param {Array} stagingArea - the staging area for skipped keys
 * @param {DecryptionCallback} callback - the function to call with the decrypted message or an error
 */
function attemptDecryptionUsingDerivedKeyMaterial(dsrc, 
    state, ciphertext, hdr, key, purportedHeaderKey, stagingArea, callback) 
{
    //TODO: nonce in encrypted message
    var purportedRootKey = key.slice(0, key.length / 3);
    var purportedNextHeaderKey = key.slice(key.length / 3, 2 * key.length / 3);
    var purportedChainKey = key.slice(2 * (key.length / 3));
    var keys = stage_skipped_header_and_message_keys( stagingArea,
            purportedHeaderKey, 0, hdr.msg_number, purportedChainKey
        );
    stagingArea = keys.stagingArea;
    purportedChainKey = keys.CKp;
    var plaintext = decryptBody(keys.MK, ciphertext.body);
    if (plaintext instanceof Error) {
        mu.log('Error: Failed to decrypt message body with purported message key (2).',
        '\n\t', plaintext.message);
        callback(plaintext);
    } else {
        state = advanceRatchetRecv(state, purportedRootKey, purportedHeaderKey, 
            purportedNextHeaderKey, hdr.dh_ratchet_key);
        finish(dsrc, stagingArea, plaintext, hdr.msg_number, purportedChainKey, callback);
    }
}

/**
 * @description Handle a message decryption when the current header key for reception was not
 *  fit to decode the header of the message. Will include deriving new key material and ratcheting
 *
 * @param {DataSource} dsrc - the data source for the AxolotlState
 * @param {AxolotlState} state - the state for the client
 * @param {CiphertextMessage} ciphertext - the encrypted message object
 * @param {Array} stagingArea - the staging area for skipped keys
 * @param {DecryptionCallback} callback - the function to call with the decrypted message or an error
 */
function handleWithoutKey(dsrc, state, ciphertext, stagingArea, callback) {
    //TODO: nonce in encrypted message
    mu.debug("handleWithoutKey: key:", state.next_header_key_recv);
    var purportedHdr = decryptHeader(state.next_header_key_recv, ciphertext.head);
    if (purportedHdr instanceof Error) {
        mu.log('Error: Failed to decrypt message header with next_header_key_recv.','\n\t', purportedHdr.message);
        callback(purportedHdr);
    } else if (purportedHdr.length != 3) {
        var errmsg = 'Decrypted header has unexpected format.';
        handlePotentialError(new Error(errmsg), errmsg, callback);
    } else {
        var hdr = parseHeader(purportedHdr);
        if (state.chain_key_recv) { // else we have never established a key with which to decrypt any messages anyway.
            stagingArea = stage_skipped_header_and_message_keys(stagingArea, state.header_key_recv, 
                state.counter_recv, hdr.prev_msg_number, 
                state.chain_key_recv,
                true).stagingArea;
                // Trevor Perrin (Axolotl master mind) answered that this it is 
                // correct to ignore this when no chain key is present.
        }
        var purportedHeaderKey = state.next_header_key_recv;
        var purportedRootKey, purportedNextHeaderKey, purportedChainKey;
        var dh = sodium.crypto_scalarmult(
                state.dh_ratchet_key_send,
                new Buffer(hdr.dh_ratchet_key, 'base64')),
            input = cu.hmac(state.root_key, dh);
        cu.hkdf(input, 'MobileEdge Ratchet', 3*32, function keyDerivationCallback(key) {
            attemptDecryptionUsingDerivedKeyMaterial(dsrc, 
                state, ciphertext, hdr, key, purportedHeaderKey, stagingArea, callback);
        });
    }

}

/** 
 * @callback DecryptionCallback 
 * @param {?Error} err the error if an error occurred
 * @param {?String} plaintext the decrypted message if decryption was
 *  successful
 */

/**
 * @description Takes an encrypted message and an identifier of the sender and decrypts the
 *  message, advancing the Axolotl state as necessary.
 *
 * @param {String} identity - the public identity key (base64) of the sender 
 * @param {CiphertextMessage} ciphertext - the ciphertext object of the received message
 * @param {DecryptionCallback} callback the function to be called when decryption is 
 *  finished or it fails. Takes an err parameter, to indicate any errors(m, a
 *  cleartext parameter with the decrypted message, as well as the new
 *  state (AxolotlState) which the application should save to persistent
 *  storage.
 */
exports.recvMessage = 
function recvMessage(identity, ciphertext, callback) {
    //TODO: nonce in encrypted message
    mu.debug('IN RECEIVE:', ciphertext);
    var dsrc = new DataSource();
    dsrc.axolotl_state.get(new Buffer(identity, 'base64'), function(err, state) {
        if (!state) {
            return callback(new Error('recvMessage: could not find state for id '+identity))
        }
        /**
         * Staging area for skipped header and message keys.
         */
        var stagingArea = [],
            plaintext = try_skipped_header_and_message_keys(state, ciphertext);
        if (!(plaintext instanceof Error)) { // we found a skipped key and decryption succeeded.
            callback(null, plaintext.msg, plaintext.state);
            return;
        }
        var purportedHdr;
        mu.debug("recvMessage: key:", state.header_key_recv);
        if (state.header_key_recv  // we have a key which we can decrypt received headers with
            && !((purportedHdr = decryptHeader(state.header_key_recv, ciphertext.head)) instanceof Error)) {
            handleWithExistingKey(dsrc, state, ciphertext, purportedHdr, stagingArea, callback);
        } else {
            if (state.ratchet_flag) { // we have not ratcheted yet so the state is inconsistent.
                var errmsg = 'Error: Inconsistent ratchet state. Did not expect ratchet_flag to be set.';
                handlePotentialError(new Error(errmsg), errmsg, callback);
            } else {
                handleWithoutKey(dsrc, state, ciphertext, stagingArea, callback);
            }
        }
    });
}

/**
 * @description Attempts to decrypt the sender's public key encrypted using (something
 *  similar to) DHIES
 *
 * @param {String} from - encrypted public identity key (base64) of the sender 
 * @param {String} eph - ephemeral public key used for DHIES
 * @param {Function} callback - the function to be called when decryption is 
 *  finished or it fails. Takes an err parameter, to indicate any errors and a 
 *  "from" parameter if decryption was successful.
 */
exports.decryptSenderInformation = function decryptSenderInformation(from, eph, callback)
{
    var dh = sodium.crypto_scalarmult(getIDKey().secretKey, new Buffer(eph, 'base64'));
    cu.hkdf(dh, 'MobileEdge PubKeyEncrypt', 32, function (key) {
        var buf = Buffer.concat([new Buffer(16).fill(0), new Buffer(from, 'base64')]);
        var paddedFrom = buf.slice(0,-24);
        var nonce = buf.slice(-24);
        var decrypted = sodium.crypto_secretbox_open(key, paddedFrom, nonce);
        if (decrypted)
        {
            callback (null, decrypted);
        } 
        else
        {
            callback(new Error("Decryption of sender information failed."));
        }
    });
}

