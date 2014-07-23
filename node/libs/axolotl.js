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
var newDHParam = nacl.crypto_box_keypair;

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
    return mu.map(nacl.from_hex, id);
};

/**
 * @description 
 * Generate (and print) a new (permanent) ID key for use in the Axolotl ratchet protocol.
 * Prints the Base64-encoded JSON of the object that is returned.
 *
 * This function is likely not used in production and may be moved to a different place
 * soon.
 * 
 * @return {Object} An object containing boxSk and boxPk, both as hex string.
 */
var generateIDKey = function() {
    var params = newDHParam();
    params.boxSk = nacl.to_hex(params.boxSk);
    params.boxPk = nacl.to_hex(params.boxPk);
    mu.debug('Buff:', (new Buffer(JSON.stringify(params))).toString('base64'));
    return params;
};

/**
 * @description Saves a given public key for a given ID token to the database.
 * 
 * @param {Object} id_token the identity token of the client
 * @param {Object} keyExchangeMsg the client's new public key we want to store
 * @param {Function} callback the function to call when we (successfully or not)
 *  finished storing the public key.
 */
exports.makeIdentity = 
function makeIdentity(id_token, keyExchangeMsg, callback) {
    var ident = new Identity();
    var conn = global.db_conn;//mongoose.connect('mongodb://localhost/keys');
    ident.id_mac = id_token['mac'];
    ident.id_expires = id_token['info']['expires'];
    ident.pubkey = keyExchangeMsg['pubkey']; //FIXME: remove this field?
    ident.axolotl_state = axolotlKeyAgreement(keyExchangeMsg); //FIXME: this will not work at all...
    ident.save(callback);
}

/**
 * @description Key derivation wrapper just for Bob.
 * 
 * @param {Object} mine Bob's key exchange message
 * @param {Object} their Alice's key exchange message
 * @param {Function} callback function to call when done
 */
var deriveKeysBob = exports.deriveKeysBob =
function deriveKeysBob(mine, their, callback) {
    var part1 = nacl.to_hex(nacl.crypto_scalarmult(mine.eph0.boxSk, their.id)),
        part2 = nacl.to_hex(nacl.crypto_scalarmult(mine.id.boxSk, their.eph0)),
        part3 = nacl.to_hex(nacl.crypto_scalarmult(mine.eph0.boxSk, their.eph0));
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
    var part1 = nacl.to_hex(nacl.crypto_scalarmult(mine.id.boxSk, their.eph0)),
        part2 = nacl.to_hex(nacl.crypto_scalarmult(mine.eph0.boxSk, their.id)),
        part3 = nacl.to_hex(nacl.crypto_scalarmult(mine.eph0.boxSk, their.eph0));
    deriveKeys(part1, part2, part3, callback)
}

/**
 * @description Key derivation wrapper common to Alice and Bob.
 * 
 * @param {String} part1 first part of the input material
 * @param {String} part2 second part of the input material
 * @param {String} part3 third part of the input material
 * @param {Function} callback function to call when done
 */
function deriveKeys(part1, part2, part3, callback) {
    var master_key = nacl.crypto_hash(nacl.from_hex(part1+part2+part3)); // Note that this is SHA512 and not SHA256. It does not have to be.
    cu.hkdf(master_key, 'MobileEdge', 5*32, function(key){
        res = {
            'rk'    : key.substr(0, key.length / 5),
            'hk'   : key.substr(key.length / 5, key.length / 5),
            'nhk0'   : key.substr(2 * key.length / 5, key.length / 5),
            'nhk1'  : key.substr(3 * key.length / 5, key.length / 5),
            'ck'  : key.substr(4 * key.length / 5)
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
    var theirId = nacl.from_hex(keyExchangeMsg['id']),                     // A
        theirEph0 = nacl.from_hex(keyExchangeMsg['eph0']),                   // A_0
        theirEph1 = null;                   // A_1 (unused, remove?)
    // Axolotl generates master_key = H (DH(A,B_0) || DH(A_0,B) || DH(A_0,B_0))
    deriveKeysBob({ 'id': myId, 'eph0' : myEph0, 'eph1' : myEph1 },
                mu.map(nacl.from_hex, keyExchangeMsg), function(res) {
        state.id_mac                = nacl.to_hex(keyExchangeMsg.id_mac);
        state.root_key              = res.rk;
        state.chain_key_send        = res.ck; // Server is Bob. So we set CKs first.
        state.header_key_send       = res.hk;
        state.next_header_key_recv  = res.nhk0;
        state.next_header_key_send  = res.nhk1;
        state.dh_identity_key_send  = nacl.to_hex(myId.boxPk);
        state.dh_identity_key_recv  = nacl.to_hex(theirId);
        state.dh_ratchet_key_send   = nacl.to_hex(myEph1.boxSk);   // Storing secret (private) key here. Should we store the whole key pair instead?
        state.dh_ratchet_key_send_pub = nacl.to_hex(myEph1.boxPk);
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
                    'id': nacl.to_hex(myId.boxPk), 
                    'eph0' : nacl.to_hex(myEph0.boxPk), 
                    'eph1': nacl.to_hex(myEph1.boxPk)
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
 *  The objects each contain a boxSk and a boxPk field.
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
    var theirId = nacl.from_hex(keyExchangeMsg['id']),                     // B
        theirEph0 = nacl.from_hex(keyExchangeMsg['eph0']),                 // B_0
        theirEph1 = nacl.from_hex(keyExchangeMsg['eph1']);                 // B_1 
    // Axolotl generates master_key = H (DH(A,B_0) || DH(A_0,B) || DH(A_0,B_0))
    deriveKeysAlice({ 'id': myId, 'eph0' : myEph0 },
                mu.map(nacl.from_hex, keyExchangeMsg), function(res) {
        callback(null, res)
    });
}

/**
 * @description Advance the ratchet state with the given client when sending a message.
 * @param {AxolotlState} state the AxolotlState associated with the receiver
 * @param {Function} callback the function to call when ratcheting is done.
 */
function advanceRatchetSend(state, callback) {
    var updatedKey = newDHParam();
    state.dh_ratchet_key_send = nacl.to_hex(updatedKey.boxSk);
    state.dh_ratchet_key_send_pub = nacl.to_hex(updatedKey.boxPk);
    state.header_key_send = state.next_header_key_send;
    var dh =  nacl.to_hex(nacl.crypto_scalarmult(
                nacl.from_hex(state.dh_ratchet_key_send),
                nacl.from_hex(state.dh_ratchet_key_recv))),
        input = cu.hmac(nacl.from_hex(state.root_key), dh)
    cu.hkdf(input, 'MobileEdge Ratchet', 3*32, function (key) {
        state.root_key = key.substr(0, key.length / 3);
        state.next_header_key_send = key.substr(key.length / 3, key.length / 3);
        state.chain_key_send = key.substr(2 * (key.length / 3));
        
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
 * @param {string} state - the Axolotl state associated with the recipient of the message.
 * @param {string} msg - the message to be encrypted and sent
 * @param {EncryptionCallback} callback - the function to be called once the msg is safely encrypted
 *  Takes an error parameter (if, for instance, encryption is not possible) and
 *  the ciphertext, as well as the new state (AxolotlState) the application
 *  is responsible of saving to persistent storage.
 */
exports.sendMessage =
function sendMessage(id_mac, msg, callback) {
    var dsrc;
    function workerSend(state) {
        var msgKey = cu.hmac(nacl.from_hex(state.chain_key_send), "0"),
            nonce1 = nacl.crypto_secretbox_random_nonce(),
            nonce2 = nacl.crypto_secretbox_random_nonce(),
            msgBody = nacl.crypto_secretbox(
                        nacl.encode_utf8(msg),
                        nonce1,
                        msgKey),
            msgHead = nacl.crypto_secretbox( //TODO: real concatenation of to 32bit ints here!
                        nacl.encode_utf8(
                            JSON.stringify([state.counter_send,
                                state.previous_counter_send,
                                state.dh_ratchet_key_send_pub,
                                nacl.to_hex(nonce1)])),
                        nonce2,
                        nacl.from_hex(state.header_key_send));
        var ciphertext = {
            'nonce' : nacl.to_hex(nonce2),
            'head'  : nacl.to_hex(msgHead),
            'body'  : nacl.to_hex(msgBody)
                //TODO mac!?
        }
        state.counter_send += 1;
        state.chain_key_send = nacl.to_hex(cu.hmac(nacl.from_hex(state.chain_key_send), "1"));
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
    dsrc.axolotl_state.get(id_mac, function(err, state){
        if (!state) {
            mu.debug("Error:", "No state for this client present. Could not even fetch it myself.\nID:", id_mac);
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
 * @param {String} purportedRootKey the purported new root key to be written to the state
 * @param {String} purportedHeaderKey the purported new header key to be written to the state
 * @param {String} purportedNextHeaderKey the purported new next header key to be 
 *  written to the state
 * @param {String} purportedDHRatchetKey the purported DH ratchet key to be written to the state
 * @return {AxolotlState} the new state.
 */
function advanceRatchetRecv(state, purportedRootKey, purportedHeaderKey, 
        purportedNextHeaderKey, purportedDHRatchetKey) {
    state.root_key = purportedRootKey;
    state.header_key_recv = purportedHeaderKey;
    state.next_header_key_recv = purportedNextHeaderKey;
    state.dh_ratchet_key_recv = purportedDHRatchetKey;
    state.dh_ratchet_key_send = null;
    state.dh_ratchet_key_send_pub = null;
    state.ratchet_flag = true;
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
        var purportedHdr = decryptHeader(state.skipped_hk_mk[i].hk, msg.head, msg.nonce);
        if (purportedHdr instanceof Error) { // this skipped header key was not the right one
            continue;
        }
        var purportedNonce = purportedHdr[3];
        var plainMsg = decryptBody(state.skipped_hk_mk[i].mk, msg.body, purportedNonce);
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
 * @param {String} HKr the header key for reception
 * @param {Number} Nr the "old" message counter
 * @param {Number} Np purported "new" message counter
 * @param {String} CKr the (reception) chain key
 * @return {Object} an object containing the last computed chain key, message key, and
 *  the possibly populated staging area.
 */
function stage_skipped_header_and_message_keys(stagingArea, HKr, Nr, Np, CKr, stage_result) {
    var msgKey,
        headerKey = HKr,
        chainKey = nacl.from_hex(CKr);
    for (var i = Nr; i < Np; i++) {
        // Each message will have a different MK derived from the chain key.
        msgKey = cu.hmac(chainKey, "0");
        // The chain key will also be derived and renewed in each step.
        chainKey = cu.hmac(chainKey, "1");
        stagingArea.push({
            'timestamp' : Date.now(),    //might be unnecessary.
            'hk' : headerKey, 
            'mk': nacl.to_hex(msgKey)
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
            'mk': nacl.to_hex(msgKey)
        });
    }
    return { 'CKp' : nacl.to_hex(chainKey), 'MK' : nacl.to_hex(msgKey), 'stagingArea' : stagingArea };
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
    state.skipped_hk_mk = state.skipped_hk_mk.concat(stagingArea);
    return state;
}

/**
 * @description Decrypts a header ciphertext with a given key and corresponding nonce.
 *
 * @param {String} key - the header key
 * @param {String} ciphertext - the encrypted message header
 * @param {String} nonce - the corresponding nonce
 * @return {Error|Array} either an Error if decryption failed, or the Array object corresponding
 *  to the decrypted header.
 */
function decryptHeader(key, ciphertext, nonce) {
    var plainHdr;
    try { //TODO: use domains instead, not try/catch!
        plainHdr = nacl.crypto_secretbox_open(
                nacl.from_hex(ciphertext), 
                nacl.from_hex(nonce), 
                nacl.from_hex(key));
    } catch (err) {
        return new Error('Header decryption failed' + err);
    }
    try {
        var header = JSON.parse(nacl.decode_utf8(plainHdr));
        return header;
    } catch (err) {
        mu.log('Invalid header format!', err.message);
        return new Error('Invalid header format:' + err.message);
    }
}

/**
 * @description Decrypts a message body ciphertext, given a corresponding key and nonce.
 *
 * @param {String} key - the message key
 * @param {String} ciphertext - the message ciphertext
 * @param {String} nonce - the corresponding nonce
 * @return {Error|String} either an Error if decryption failed, or a String containing 
 *  the decrypted message.
 */
function decryptBody(key, ciphertext, nonce) {
    var plaintext;
    try { //TODO: use domains instead, not try/catch!
        plaintext = nacl.crypto_secretbox_open(nacl.from_hex(ciphertext),
                nacl.from_hex(nonce), nacl.from_hex(key));
    } catch (err) {
        //mu.debug(err, key, ciphertext, nonce);
        return new Error(err.message);
    }
    return nacl.decode_utf8(plaintext);
}

/**
 * @description Finishes decryption and state update, independent of the method used to 
 * decrypt the message. Calls the recv functions callback for it.
 * @param {AxolotlState} state - the state
 * @param {String} plaintext - the plaintext of the message
 * @param {Number} Np - message counter to update the one in the state with
 * @param {String} CKp - the new purported chain key to save to the state
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
    return {
        'msg_number'        : header[0],
        'prev_msg_number'   : header[1],
        'dh_ratchet_key'    : header[2],
        'nonce'             : header[3]
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
    var hdr = parseHeader(purportedHdr);
    var keys = stage_skipped_header_and_message_keys(stagingArea, state.header_key_recv, 
            state.counter_recv, hdr.msg_number, state.chain_key_recv);
    var purportedChainKey = keys.CKp;
    var plaintext = decryptBody(keys.MK, ciphertext.body, hdr.nonce);
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
 * @param {String} key - the derived key material
 * @param {String} purportedHeaderKey - the purported header key. Needed to update ratchet.
 * @param {Array} stagingArea - the staging area for skipped keys
 * @param {DecryptionCallback} callback - the function to call with the decrypted message or an error
 */
function attemptDecryptionUsingDerivedKeyMaterial(dsrc, 
    state, ciphertext, hdr, key, purportedHeaderKey, stagingArea, callback) 
{
    var purportedRootKey = key.substr(0, key.length / 3);
    var purportedNextHeaderKey = key.substr(key.length / 3, key.length / 3);
    var purportedChainKey = key.substr(2 * (key.length / 3));
    var keys = stage_skipped_header_and_message_keys( stagingArea,
            purportedHeaderKey, 0, hdr.msg_number, purportedChainKey
        );
    stagingArea = keys.stagingArea;
    purportedChainKey = keys.CKp;
    var plaintext = decryptBody(keys.MK, ciphertext.body, hdr.nonce);
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
    var purportedHdr = decryptHeader(state.next_header_key_recv, ciphertext.head, ciphertext.nonce);
    if (purportedHdr instanceof Error) {
        mu.log('Error: Failed to decrypt message header with next_header_key_recv.','\n\t', purportedHdr.message);
        callback(purportedHdr);
    } else if (purportedHdr.length != 4) {
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
        var dh = nacl.to_hex(nacl.crypto_scalarmult(
                nacl.from_hex(state.dh_ratchet_key_send),
                nacl.from_hex(hdr.dh_ratchet_key))),
            input = cu.hmac(nacl.from_hex(state.root_key), dh);
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
 * @param {String} id_mac - the id_mac of the sender 
 * @param {String} ciphertext - the ciphertext of the received message.
 * @param {DecryptionCallback} callback the function to be called when decryption is 
 *  finished or it fails. Takes an err parameter, to indicate any errors(m, a
 *  cleartext parameter with the decrypted message, as well as the new
 *  state (AxolotlState) which the application should save to persistent
 *  storage.
 */
exports.recvMessage = 
function recvMessage(id_mac, ciphertext, callback) {
    var dsrc = new DataSource();
    dsrc.axolotl_state.get(id_mac, function(err, state) {
        if (!state) {
            return callback(new Error('recvMessage: could not find state for id '+id_mac))
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
        if (state.header_key_recv  // we have a key which we can decrypt received headers with
            && !((purportedHdr = decryptHeader(state.header_key_recv, ciphertext.head, ciphertext.nonce)) instanceof Error)) {
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

