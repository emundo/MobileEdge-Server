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
