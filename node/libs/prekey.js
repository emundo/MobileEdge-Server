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
 * Created by Raphael Arias on 2014-06-06.
 */

/**
 * @module prekey
 * @description Prekey handling on the server side. Includes prekey storage and prekey recovery.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

var myutil = require('./util.js'),
    ds = require('../models/DataSourceMongoose.js');

var DataSource = ds.DataSource;

/**
 * @callback PrekeyPutCallback
 * @param {?Error} err - an error if the prekey could not be saved to storage 
 */
/**
 * Put a client-sent prekey into the state.
 *
 * @param {String} id_mac the client's identifier
 * @param {String} key_id - the id the key will be known by
 * @param {String} base_key - the prekey the client is sending
 * @param {PrekeyPutCallback} callback the function to call when prekey was successfully added
 */
exports.put =
function put(id_mac, key_id, base_key, callback) {
    var dsm = new DataSource();
    dsm.prekeys.put(id_mac, key_id, base_key, callback);
}

/**
 * @callback PrekeyGetCallback
 * @param {?Error} err - an error if the prekey could not be retrieved from storage
 * @param {?Prekey} prekey - the prekey retrieved from storage
 */
/**
 * Request a prekey for a given identity. This must update the identity in 
 * storage such that the key is never handed out again.
 * @param {String} id_mac the identifier of the client whose prekey is requested.
 * @param {PrekeyGetCallback} callback the function to call when prekey was retrieved or 
 *  an error occurred.
 */
exports.get =
function get(id_mac, callback) {
    var dsm = new DataSource();
    dsm.prekeys.get(id_mac, callback);
}
