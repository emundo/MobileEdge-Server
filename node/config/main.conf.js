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
 * Created by Raphael Arias on 2014-12-12.
 */
var config = {
    /* 
     * which IP/hostname should the MobileEdge
     * server forward the requests to?
     */
    host : '0.0.0.0',
    /* 
     * on which port is the backend server listening (TCP) 
     */
    port : 8888, 
    /*
     * path to ssl key file:
     */
    serverKey : './ssl/key.pem',
    /*
     * path to ssl certificate:
     */
    serverCertificate : './ssl/cert.pem',
    /*
     * path to ssl CA certificate:
     */
    CACertificate : './ssl/cert.pem',
};

exports.mainConfiguration = config; 



