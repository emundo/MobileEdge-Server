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
 * @file Schema definition 
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */
var mongoose = require('mongoose'),
    Schema = mongoose.Schema;

/**
 * Schema definition
 */
var Prekey = new Schema({
    id_mac      : { type: String, required: true, index: true },
    timestamp   : { type: Date, 'default': Date.now, index: true},
    key_id      : { type: Number, required: true, unique: true },
    base_key    : { type: String, required: true }
});

/**
 * Schema definition of skipped header and corresponding message keys.
 */
var Skipped = new Schema({
    timestamp   : { type: Date, default: Date.now, index: true },
    hk  : String,
    mk  : String
});

/**
 * Schema definition of the state of the Axolotl Ratchet.
 */
var AxolotlState = new Schema({
    id_mac              : { type: String, required: true, index: { unique: true } },
    root_key            : String,
    header_key_send     : String,
    header_key_recv     : String,
    next_header_key_send: String,
    next_header_key_recv: String,
    chain_key_send      : String,
    chain_key_recv      : String,
    dh_identity_key_send: String,
    dh_identity_key_recv: String,
    dh_ratchet_key_send : String,
    dh_ratchet_key_send_pub : String,
    dh_ratchet_key_recv : String,
    counter_send        : Number,
    counter_recv        : Number,
    previos_counter_send: Number,
    ratchet_flag        : Boolean,
    skipped_hk_mk       : [Skipped]
});

/**
 * Schema definition of a client identity.
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
