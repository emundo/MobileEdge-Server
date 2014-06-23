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
 * Created by Raphael Arias on 2014-06-23.
 */

/**
 * @file DataSource implementation for mongoose.
 * Extend the DataSource prototype with the functions we need.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

var mongoose = require('mongoose'),
    myutil = require('../libs/util.js'),
    schema = require('../models/schema.js'),
    ds = require('../models/DataSource.js');
var Identity = mongoose.model('Identity'),
    Prekey = mongoose.model('Prekey'),
    AxolotlState = mongoose.model('AxolotlState');

var DataSource = ds.DataSource;

exports.DataSource = DataSource;
// DataSource.prototype.axolotl_state.internal
DataSource.prototype.axolotl_state.get =
function get(id_mac, callback) {
    var promise = AxolotlState.findOne({'id_mac' : id_mac});
    promise.onFulfill(function(state){
        this.internal = state;
        callback(null, this.internal);
    });
}

DataSource.prototype.axolotl_state.create =
function create() {
    this.internal = new AxolotlState();
    //callback(null, this.axolotl_state.internal);
    return this.internal;
}

DataSource.prototype.axolotl_state.save =
function save(callback) {
    if (!this.internal) {
        var msg = 'Error: save on an uninitialized DataSource.';
        myutil.log(msg);
        callback(new Error(msg));
    }
    this.internal.save(function (err, doc, numAffected) {
        if (err) {
            myutil.log(err);
            callback(err);
            return;
        }
        callback(null, doc, numAffected);
    });
}

/**
 * 
 */
DataSource.prototype.prekeys.get =
function get(id_mac, callback) {
    Prekey.findOneAndRemove({ 'id_mac': id_mac }, 
            {'sort' : {'timestamp' : 1}}, function (err, doc) {
        if (err) {
            myutil.log(err);
            callback(err);
            return;
        }
        callback(null, doc);
    });
}

DataSource.prototype.prekeys.put =
function put(id_mac, key_id, base_key, callback) {
    var pk = new Prekey();
    pk.id_mac = id_mac;
    pk.key_id = key_id;
    pk.base_key = base_key;
    pk.save(function(err, doc, numAffected) {
        if (err) {
            myutil.log(err);
            callback(err);
            return;
        }
        callback(null)
    });
}
