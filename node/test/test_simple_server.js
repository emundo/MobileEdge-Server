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
 * Created by Raphael Arias on 2014-12-11.
 */
var net = require('net');
var mongoose = require('mongoose');

var HOST = '127.0.0.1';
var PORT = 6969;
var dbConfig = require('../config/db.conf.js').dbConfiguration;

global.db_conn = mongoose.connect('mongodb://'+dbConfig.host + '/' + 'messages');

function saveMessageForUser(message, user)
{
    
}

net.createServer(function(sock) {
    console.log('CONNECTED: ' + sock.remoteAddress +':'+ sock.remotePort);
    
    sock.on('data', function(data) {
        //console.log('DATA ' + sock.remoteAddress + ':', data);
        sock.write('You said "' + data + '"');
    });
    sock.on('end', function(data) {
        //console.log('Ended by client: ' + sock.remoteAddress +' '+ sock.remotePort);
    });
    sock.on('close', function(data) {
        //console.log('CLOSED: ' + sock.remoteAddress +' '+ sock.remotePort);
    });
}).listen(PORT, HOST);

console.log('Server listening on ' + HOST +':'+ PORT);
