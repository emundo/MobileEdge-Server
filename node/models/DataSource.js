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
 * @module DataSource
 * @description DataSource prototype definition and implementation
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

/**
 * @constructor DataSource
 * @description DataSource constructor/prototype.
 * DataSource is an "abstract" object which serves to allow database
 * access without directly interacting with the database.
 * Currently, we define one implementation of DataSource using
 * mongoose to access the MongoDB database. To use MongoD with a
 * different database, another implementation of DataSource needs to
 * be provided. The DataSource object is expected to have the
 * following functions:
 * DataSource.axolotl_state.get(id_mac, callback)
 *  retrieves the state for a given client.
 * DataSource.axolotl_state.create()
 *  creates a new AxolotlState object that the DataSource will work with.
 * DataSource.axolotl_state.save(callback)
 *  saves the current AxolotlState back to persistent storage.
 * DataSource.prekeys.get(id_mac, callback)
 *  retrieves AND DELETES a prekey for a given client.
 * DataSource.prekeys.put(id_mac, key_id, base_key, callback)
 *  inserts a new prekey into the database.
 */
var DataSource = 
exports.DataSource =
function DataSource() {
    var axolotl_state = {}
}

DataSource.prototype.axolotl_state = {};
DataSource.prototype.prekeys = {}
