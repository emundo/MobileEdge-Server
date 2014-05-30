/**
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
 * @file lala
 * @author Raphael Arias
 */

/**
 * @file Axolotl key agreement and ratcheting as described in
 *  https://github.com/trevp/axolotl/wiki.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */
var mongoose = require('mongoose'),
    fs = require('fs'),
    mu = require('./util.js'),
    cu = require('./crypto_util.js'),
    schema = require('../models/schema.js');

var Identity = mongoose.model('Identity'),
    AxolotlState = mongoose.model('AxolotlState');

/**
 * (Synchronously) get the Axolotl ID key from a file. This is needed for the key exchange.
 * @return the ID key as an object containing two Uint8Arrays.
 */
var getIDKey = function() {
    var str = fs.readFileSync('./private_ec_id', {encoding: 'utf8'});
    var buf = new Buffer(str, 'base64');
    var id = JSON.parse(buf.toString('utf8'));
    return mu.map(nacl.from_hex, id);
    // return {'boxSk': nacl.from_hex(id.boxSk), 'boxPk': nacl.from_hex(id.boxPk)};
};

/**
 * Generate (and print) a new (permanent) ID key for use in the Axolotl ratchet protocol.
 * Prints the Base64-encoded JSON of the object that is returned.
 *
 * This function is likely not used in production and may be moved to a different place
 * soon.
 * @return An object containing boxSk and boxPk, both as hex string.
 */
var generateIDKey = function() {
    var params = newDHParam();
    params.boxSk = nacl.to_hex(params.boxSk);
    params.boxPk = nacl.to_hex(params.boxPk);
    mu.debug('Buff:', (new Buffer(JSON.stringify(params))).toString('base64'));
    return params;
};

/**
 * Saves a given public key for a given ID token to the database.
 * @param id_token - the identity token of the client
 * @param keyExchangeMsg - the client's new public key we want to store
 * @param callback - the function to call when we (successfully or not)
 *  finished storing the public key.
 */
exports.saveKey = 
function saveKey(id_token, keyExchangeMsg, callback) {
    var ident = new Identity();
    var conn = global.db_conn;//mongoose.connect('mongodb://localhost/keys');
    ident.id_mac = id_token['mac'];
    ident.id_expires = id_token['info']['expires'];
    ident.pubkey = keyExchangeMsg['pubkey']; //FIXME: remove this field?
    ident.axolotl_state = axolotlKeyAgreement(keyExchangeMsg);
    ident.save(callback);
}

/**
 * Performs the key agreement according to the axolotl protocol.
 * Alice (the client) will initiate this key exchange, so her
 * keyExchangeMsg will be present.
 * The new AxolotlState object is created and saved to the database.
 * @param keyExchangeMsg - the object containing Alice's public identity
 *  key A, as well as her public ECDH parameter A0.
 * @param callback - the function to be called when all keys are derived.
 *  Takes an error parameter and the keyExchangeMsg to be sent to Alice,
 *  containing our public identity key B as well as our public ECDH 
 *  parameters B0, B1.
 */
exports.keyAgreement = 
function keyAgreement(keyExchangeMsg, callback) {
    var state = new AxolotlState();
    var myId = getIDKey(),                  // B
        myEph0 = newDHParam(),       // B_0
        myEph1 = newDHParam();       // B_1
    var theirId = nacl.from_hex(keyExchangeMsg['id']),                     // A
        theirEph0 = nacl.from_hex(keyExchangeMsg['eph0']),                   // A_0
        theirEph1 = null;                   // A_1 (unused, remove?)
    // Axolotl generates master_key = H (DH(A,B_0) || DH(A_0,B) || DH(A_0,B_0))
    var part1 = nacl.to_hex(nacl.crypto_scalarmult(myEph0.boxSk, theirId)),
        part2 = nacl.to_hex(nacl.crypto_scalarmult(myId.boxSk, theirEph0)),
        part3 = nacl.to_hex(nacl.crypto_scalarmult(myEph0.boxSk, theirEph0));
    var master_key = nacl.crypto_hash(nacl.from_hex(part1+part2+part3)); // Note that this is SHA512 and not SHA256. It does not have to be.
    var derived = cu.hkdf(master_key, 'MobileEdge', function(res){
        state.root_key = res['first'];
        state.chain_key_send = res['last']; // Server is Bob. So we set CKs first.
        state.header_key_send = {}; //cu.hkdf();
        state.next_header_key_send = {}; //cu.hkdf();
        state.next_header_key_recv = {}; //cu.hkdf();
        state.dh_identity_key_send = nacl.to_hex(myId.boxPk);
        state.dh_identity_key_recv = nacl.to_hex(theirId);
        state.dh_ratchet_key_send_pub = nacl.to_hex(myEph1.boxSk);   // Storing secret (private) key here. Should we store the whole key pair instead?
        state.counter_send = 0;
        state.counter_recv = 0;
        state.previous_counter_send = 0;
        state.ratchet_flag = false;
        state.save(function(err) {
            if (err) { 
                mu.log('Error trying to save key agreement info in database.', err);
                callback(err);
            }
            else
                callback(null, 
                {
                    'id': nacl.to_hex(myId.boxPk), 
                    'eph0' : nacl.to_hex(myEph0.boxPk), 
                    'eph1': nacl.to_hex(myEph1.boxPk)
                }, res);
        });
    });
}

/**
 * Convenience function to generate a set of (2 public and private) parameters
 * for Alice. 
 * @return {{id: NaClBoxKeyPair, eph0: NaClBoxKeyPair}} A new object containing Alices identity key pair and an ephemeral
 *  ECDH key pair for the key exchange. The objects
 */
exports.genParametersAlice = 
function genParametersAlice() {
    return {
        'id'    : newDHParam(),
        'eph0'  : newDHParam()
    };
}
//exports.genParametersAlice = genParametersAlice;
/**
 * For testing purposes, we also need to emulate Alice (the client).
 */
exports.keyAgreementAlice =
function keyAgreementAlice(myParams, keyExchangeMsg, callback) {
    var myId = myParams.id,            // A
        myEph0 = myParams.eph0;       // A_0
    var theirId = nacl.from_hex(keyExchangeMsg['id']),                     // B
        theirEph0 = nacl.from_hex(keyExchangeMsg['eph0']),                 // B_0
        theirEph1 = nacl.from_hex(keyExchangeMsg['eph1']);                 // B_1 
    // Axolotl generates master_key = H (DH(A,B_0) || DH(A_0,B) || DH(A_0,B_0))
    var part1 = nacl.to_hex(nacl.crypto_scalarmult(myId.boxSk, theirEph0)),
        part2 = nacl.to_hex(nacl.crypto_scalarmult(myEph0.boxSk, theirId)),
        part3 = nacl.to_hex(nacl.crypto_scalarmult(myEph0.boxSk, theirEph0));
    var master_key = nacl.crypto_hash(nacl.from_hex(part1+part2+part3)); // Note that this is SHA512 and not SHA256. It does not have to be.
    var derived = cu.hkdf(master_key, 'MobileEdge', function(res){
        callback(null, res);
    });
}

/**
 * Takes a message and encrypts it to the receiver, advancing the Axolotl
 * ratchet.
 * @param {string} to - their identity token mac
 * @param {string} msg - the message to be encrypted and sent
 * @param callback - the function to be called once the msg is safely encrypted
 *  Takes an error parameter (if, for instance, encryption is not possible) and
 *  the ciphertext.
 */
exports.sendMessage =
function sendMessage(to, msg, callback) {
}

/**
 * Takes an encrypted message and an identifier of the sender and decrypts the
 * message, advancing the Axolotl state as necessary.
 * @param {string} from - the senders identity token mac
 * @param {string} ciphertext - the ciphertext of the received message.
 * @param {function} callback - the function to be called when decryption is 
 *  finished or it fails. Takes an err parameter, to indicate any errors, and
 *  the cleartext parameter with the decrypted message
 */
exports.recvMessage = 
function recvMessage(from, ciphertext, callback) {
}
var newDHParam = nacl.crypto_box_keypair;

