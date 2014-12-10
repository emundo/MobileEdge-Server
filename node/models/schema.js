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
 * @file schema.js
 * @description Schema definitions
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

/*
 * Mongoose
 */
var mongoose = require('mongoose'),
    Schema = mongoose.Schema;

/**
 * @description Schema definition of a Prekey.
 *
 * @property id_mac the id_mac associated with the prekey. This represents
 *  the identity of the user. It is a required field.
 * @property timestamp timestamp of the prekey push operation.
 * @property key_id a unique identifier for a prekey.
 * @property base_key the actual prekey (DH public parameter).
 */
var Prekey = new Schema({
    timestamp   : { type: Date, 'default': Date.now, index: true},
    key_id      : { type: String, required: true, unique: true },
    base_key    : { type: String, required: true }
});

/**
 * Schema definition of skipped header and corresponding message keys.
 *
 * These documents are created, whenever a message is received that
 * does not use the expected next header and message keys. 
 * The ratchet state is then advanced, but the skipped keys are stored
 * in the database to decrypt possibly delayed incoming messages encrypted
 * with those older keys.
 *
 * The documents contain a timestamp to allow cleaning up (garbage collection)
 * of old skipped keys, so the server does not have to keep them indefinitely.
 *
 * @property timestamp the timestamp of when the keys were skipped.
 * @property hk the skipped header key.
 * @property mk the skipped message key.
 */
var Skipped = new Schema({
    timestamp   : { type: Date, default: Date.now, index: true },
    hk  : Buffer,
    mk  : Buffer
});

/**
 *
 * @description Schema definition of the state of the Axolotl Ratchet.
 * The Axolotl state represents all the information needed in persistent
 * memory to perform the Axolotl ratchet. This includes several keys
 * for sending and receiving as well as counters of sent and received messages,
 * and additionally a flag to indicate when ratcheting has to be performed.
 *
 * @property id_mac the identifier for the client the state is associated with. This
 *  is a required and unique field and serves as an index over the documents.
 * @property root_key the root key (or RK) from the Axolotl protocol.
 * @property header_key_send the current header key (HKs) used for sending messages.
 * @property header_key_recv the current header key (HKr) used for receiving messages.
 * @property next_header_key_send the next header key (NHKs) to be used after the current
 *  one for sending messages.
 * @property next_header_key_recv the next header key (NHKr) to be used after the current
 *  one for receiving messages.
 * @property chain_key_send the current chain key used for sending messages (CKs).
 * @property chain_key_recv the current chain key used for receiving messages (CKr).
 * @property dh_identity_key_send the identity key used for sending (DHIs). This
 *  corresponds to our own private identity key.
 * @property dh_identity_key_recv the identity key used for receiving messages (DHIr).
 *  This corresponds to the public identity key of the client.
 * @property dh_ratchet_key_send the current EC-Diffie-Hellman ratchet key (DHRs)
 *  used for sending messages. This is our local private key.
 * @property dh_ratchet_key_send_pub the public DH parameter corresponding to
 *  dh_identity_key_send.
 * @property dh_ratchet_key_recv the ratchet key used for receiving messages (DHRr).
 *  This corresponds to the client's public DH parameter.
 * @property counter_send the counter of messages sent under the current ratchet (Ns).
 * @property counter_recv the counter of messages received unter the current 
 *  ratchet (Nr).
 * @property previos_counter_send the counter of messages sent under the 
 *  previous ratchet (PNs).
 * @property ratchet_flag the flag specifying whether ratcheting should take place
 *  on the next message send.
 * @property skipped_hk_mk the skipped header and message keys to be checked upon
 *  reception of a message.
 */
var AxolotlState = new Schema({
    dh_identity_key_recv: { type: Buffer, required: true, index: { unique: true } },
    dh_identity_key_send_pub: Buffer,
    dh_identity_key_send: Buffer,
    root_key            : Buffer,
    header_key_send     : Buffer,
    header_key_recv     : Buffer,
    next_header_key_send: Buffer,
    next_header_key_recv: Buffer,
    chain_key_send      : Buffer,
    chain_key_recv      : Buffer,
    dh_ratchet_key_send : Buffer,
    dh_ratchet_key_send_pub : Buffer,
    dh_ratchet_key_recv : Buffer,
    counter_send        : Number,
    counter_recv        : Number,
    previos_counter_send: Number,
    ratchet_flag        : Boolean,
    skipped_hk_mk       : [Skipped]
});

/**
 * @description Schema definition of a client identity.
 * This is not really used anymore and a candidate for removal. Most
 * of the information is contained in the AxolotlState and the Prekeys
 * do not have to be referenced in one place like this anyway.
 * I am leaving this here for the moment, as I am not fully convinced yet.
 */
var Identity = new Schema({
    id_mac          : { type: String, required: true, index: { unique: true } },
    id_expires      : { type: Date, required: true, index: true },
    pubkey          : { type: String, required: true },
    axolotl_state   : { type: Schema.ObjectId, ref: 'AxolotlState' },
    max_prekey      : { type: Number, default: 0},
    prekeys         : [Prekey]
});

mongoose.model('Prekey', Prekey);
mongoose.model('Skipped', Skipped);
mongoose.model('Identity', Identity);
mongoose.model('AxolotlState', AxolotlState);
