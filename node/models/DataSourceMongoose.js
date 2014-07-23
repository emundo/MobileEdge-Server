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
 * @module DataSourceMongoose
 * @description DataSource implementation for mongoose.
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

/*
 * The original DataSource.
 */
var DataSource = ds.DataSource;

/**
 * @constructor DataSourceMongoose
 * @description Constructor for the DataSourceMongoose instance.
 */
function DataSourceMongoose() {
    /**
     * Operations for the axolotl states.
     *
     * @property {Function} create {@link module:DataSourceMongoose."axolotl_state.create"}
     * @property {Function} get {@link module:DataSourceMongoose."axolotl_state.get"}
     * @property {Function} retrieve {@link module:DataSourceMongoose."axolotl_state.retrieve"}
     * @property {Function} save {@link module:DataSourceMongoose."axolotl_state.save"}
     */
    this.axolotl_state = { get : get, save : save, create : create, retrieve : retrieve };
    /**
     * Operations for the prekeys.
     *
     * @property {Function} get {@link module:DataSourceMongoose."prekey.get"}
     * @property {Function} put {@link module:DataSourceMongoose."prekey.put"}
     */
    this.prekeys = { get : pkget, put : pkput };
}

/*
 * "Inherit" from the super-class DataSource.
 */
DataSourceMongoose.prototype = new DataSource();

/*
 * Export our own version of the DataSource.
 */
exports.DataSource = DataSourceMongoose;

/**
 * @alias module:DataSourceMongoose."axolotl_state.get"
 * @description The implementation to get an Axolotl state from
 *  MongoDB using mongoose.
 *
 * @param {String} id_mac the identifier for the client whose state we want
 * @param {GeneralCallback} callback the function to call when the state was retrieved or an
 *  error occurred.
 */
function get(id_mac, callback) {
    var handle = this;
    AxolotlState.findOne({'id_mac' : id_mac}, function(err, state){
        if (err) {
            myutil.log('Error getting AxolotlState from Mongoose:', err);
            callback(err);
        } else if (!state) {
            callback(new Error('state not found in db when looking for id_mac:' + id_mac));
        } else {
            //myutil.log("ERR", err , "+", "STATE", state, '+ TEST', test)
            handle.internal = state;
            callback(null, handle.internal);
        }
    });

}

/**
 * @alias module:DataSourceMongoose."axolotl_state.retrieve"
 * @description retrieve the internal state.
 *
 * @return {AxolotlState} the internal axolotl state.
 */
function retrieve() {
    if (!this.internal) {
        myutil.log('Error getting AxolotlState. Not here yet');
    } else {
        return this.internal;
    }
}

/**
 * @alias module:DataSourceMongoose."axolotl_state.create"
 * @description The implementation to create an Axolotl state suitable for
 *  MongoDB using the mongoose model AxolotlState.
 *
 * @return {AxolotlState} the new AxolotlState
 */
function create() {
    this.internal = new AxolotlState();
    //callback(null, this.axolotl_state.internal);
    return this.internal;
}

/**
 * @alias module:DataSourceMongoose."axolotl_state.save"
 * @description The implementation to save an Axolotl state to
 *  MongoDB using mongoose.
 *
 * @param {GeneralCallback} callback the function to call when the save operation succeeded or failed.
 */
function save(callback) {
    if (!this.internal) {
        var msg = 'Error: save on an uninitialized DataSource.';
        myutil.log(msg);
        callback(new Error(msg));
    } else {
        //myutil.debug("DataSource saving: ", this.internal.id_mac);
        this.internal.save(function (err, doc, numAffected) {
            if (err) {
                myutil.log(err);
                callback(err);
            } else {
                //myutil.debug('DataSource save finished for ID:', doc.id_mac);
                callback(null, doc, numAffected);
            }
        });
    }
}

/**
 * @alias module:DataSourceMongoose."prekey.get"
 * @description The implementation to get (and atomically delete)
 *  a prekey from MongoDB using mongoose.
 *
 * @param {String} id_mac the identifier of the client whose prekey is requested
 * @param {PrekeyGetCallback} callback the function to call when the prekey was retrieved or
 *  an error occurred.
 */
function pkget(id_mac, callback) {
    Prekey.findOneAndRemove({ 'id_mac': id_mac }, 
            {'sort' : {'timestamp' : 1}}, function (err, doc) {
        if (err) {
            myutil.log(err);
            callback(err);
        } else {
            callback(null, doc);
        }
    });
}

/**
 * @alias module:DataSourceMongoose."prekey.put"
 * @description The implementation to put a new prekey into
 *  MongoDB using mongoose.
 *
 * @param {String} id_mac the identifier of the client thatis depositing the prekey
 * @param {String} key_id the identifier for the prekey
 * @param {String} base_key the actual key (public ECDH parameter)
 * @param {PrekeyPutCallback} callback the function to call when the prekey was stored or the
 *  operation failed.
 */
function pkput(id_mac, key_id, base_key, callback) {
    var pk = new Prekey();
    pk.id_mac = id_mac;
    pk.key_id = key_id;
    pk.base_key = base_key;
    pk.save(function(err, doc, numAffected) {
        if (err) {
            myutil.log("Err saving prekey:", err);
            callback(err);
        } else {
            callback(null);
        }
    });
}
