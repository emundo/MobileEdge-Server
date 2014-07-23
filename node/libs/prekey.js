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
 * Created by Raphael Arias on 2014-06-06.
 */

/**
 * @file Prekey handling on the server side. Includes prekey storage and prekey recovery.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

var myutil = require('./util.js'),
    ds = require('../models/DataSourceMongoose.js');

var DataSource = ds.DataSource;

/**
 * Put a client-sent prekey into the state.
 * @param id_mac the client's identifier
 * @param key_id (not really sure if we need this) the id the key will be known by
 * @param base_key the prekey the client is sending
 * @param {Function} callback the function to call when prekey was successfully added
 */
exports.put =
function put(id_mac, key_id, base_key, callback) {
    var dsm = new DataSource();
    dsm.prekeys.put(id_mac, key_id, base_key, callback);
}

/**
 * Request a prekey for a given identity. This must update the identity in 
 * storage such that the key is never handed out again.
 * @param {DataSource} data_src the object from which the state can be retrieved.
 * @param id_mac the identifier of the client whose prekey is requested.
 * @return an object containing the requested prekey //FIXME: ?
 */
exports.get =
function get(id_mac, callback) {
    var dsm = new DataSource();
    dsm.prekeys.get(id_mac, callback);
}
