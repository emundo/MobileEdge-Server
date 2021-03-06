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
 * Created by Raphael Arias on 2014-06-02.
 */
/**
 * @module main
 * @description Main file of the application. Server is started here.
 *  Provides version 0.1 of the API.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

/*
 * Require some important Node modules.
 */
var https = require('https'),
    net = require('net'),
    util = require('util'),
    fs = require('fs'),
    mongoose = require('mongoose'),
    ds = require('./models/DataSourceMongoose.js');
var DataSource = ds.DataSource;

/*
 * Require our own libraries.
 */
var proxyConfig = require('./config/proxy.conf.js').proxyConfiguration,
    mainConfig = require('./config/main.conf.js').mainConfiguration,
    dbConfig = require('./config/db.conf.js').dbConfiguration,
    myutil = require("./libs/util.js"),
    axolotl = require("./libs/axolotl.js"),
    prekey = require('./libs/prekey.js'),
    errorLib = require('./libs/error.js');

/**
 * Create a database connection to use globally throughout the program.
 */
global.db_conn = mongoose.connect('mongodb://'+dbConfig.host + '/' + dbConfig.dbName);

var createErrorObject = errorLib.createErrorObject;
/**
 * The SSL certificates and keys need to be loaded.
 */
var sslOptions = {
  key: fs.readFileSync(mainConfig.serverKey),
  cert: fs.readFileSync(mainConfig.serverCertificate),
  ca: fs.readFileSync(mainConfig.CACertificate),
//  requestCert: true,
  rejectUnauthorized: false
};


const LAST_RESORT_KEY_ID = (new Buffer(8).fill(0xff)).toString('base64');


/**
 * @callback GeneralCallback
 * @param {?Error} err an error if one occurred.
 * @param {...Object} things any number of arguments (or none) might be passed here.
 */

/**
 * @callback module:main.ResponseCallback 
 * @param {module:main.MobileEdgeResponse} response - the response status code, message
 *  to send to the client
 */

/**
 * @typedef module:main.MobileEdgeResponse
 * @type Object
 *
 * @property {Number} statusCode - the HTTP status code of the response
 *  to send to the client
 * @property {Object} message - the message to send to the client
 * @property {?Boolean} toBeEncrypted - whether the response message should
 *  be encrypted. If null, this defaults to false (we cannot encrypt when we
 *  have no AxolotlState).
 */


/**
 * @description Handle a key exchange message from a client.
 * Performs the key exchange using the Axolotl protocol and saves
 * the state to persistent storage.
 *
 * @param {Object} msg the client's key exchange message
 * @param {module:main.ResponseCallback} callback the function to call when the key agreement finishes
 *  locally. 
 */
function handleKeyExchange(msg, callback) 
{
    if (!msg.keys || !msg.keys.id || !msg.keys.eph0)
    {
        callback({ 
            'statusCode' : 400,
            'message' : createErrorObject("ERROR_CODE_KEYEXCHANGE_NO_MESSAGE") 
        });
    }
    else 
    {
        var theirKeyExchange = {
            'id'    : msg.keys.id,
            'eph0'  : msg.keys.eph0
        };
        axolotl.keyAgreement(theirKeyExchange, function(err, ourKeyExchange) 
        {
            if (err) 
            {
                callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_KEYEXCHANGE_FAILURE") });
            } 
            else
            {
                callback({ 'statusCode' : 200, 'message' : ourKeyExchange });
            }
        });
    }
}

/**
 * @description Handle any encrypted message that comes from a client.
 * Dispatcher for all encrypted messages that come in. Decrypts them and
 * calls the respective handlers for the specific message type.
 * The message type is determined by looking at the type field
 * of the message, which must contain a valid message type string.
 *
 * @param {Object} msg the encrypted message
 * @param {module:main.ResponseCallback} callback - the function to call when the 
 *  message has been handled. This is usually just passed on to the next handler.
 */
function handleEncrypted(msg, callback) 
{
    function receive (from)
    {
        axolotl.recvMessage(from, msg, function(err, plaintext, state)
        {
            if (err)
            {
                myutil.debug("error decrypting:", err)
                callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_DECRYPTION_FAILURE") });
            }
            else 
            {
                var decryptedMessage = undefined;
                try 
                { // TODO: use domains instead of try/catch!
                    decrypted_msg = JSON.parse(plaintext);
                } 
                catch (err) 
                {
                    myutil.debug("decrypted plaintext:", plaintext);
                    return callback({ 
                        'statusCode' : 400, // 400: Bad Request
                        'message' : createErrorObject("ERROR_CODE_INVALID_INTERNAL_MESSAGE_FORMAT") 
                    });
                }

                if (!decrypted_msg.type)
                {
                    callback({ 
                        'statusCode' : 400, // 400: Bad Request
                        'message' : createErrorObject("ERROR_CODE_INVALID_INTERNAL_MESSAGE_TYPE") 
                    });
                }
                else
                {
                    decrypted_msg.from = from;
                    if ('PKPUSH' === decrypted_msg.type)
                    {
                        handlePrekeyPush(decrypted_msg, callback);
                    }
                    else if ('PKREQ' === decrypted_msg.type)
                    {
                        handlePrekeyRequest(decrypted_msg, callback);
                    }
                    else if ('PROXY' === decrypted_msg.type)
                    {
                        handleProxy(decrypted_msg, callback);
                    }
                    // TODO: handle other message types?
                }
            }
        });
    }
    if (msg.eph)
    { // ephemeral key attached, so assume "from" is encrypted: 
        axolotl.decryptSenderInformation(msg.from, msg.eph, function (err, from)
        {
            if (err)
            { // try again using normal "from" field
                myutil.debug("error decrypting sender information", err);
                receive(msg.from);
            }
            else
            {
                //decrypted_msg.from = from;
                msg.from = from;
                receive(from);
            }
        });
    }
    else
    {
        receive(msg.from);
    }
}

function handleProxy(msg, callback)
{
    myutil.debug('Handling proxy request.');
    const HOST = proxyConfig.host;
    const PORT = proxyConfig.port;
    const TERMINATION_SEQUENCE = proxyConfig.terminationSeq;
    var responseContent = "";
    var response = {
        'statusCode' : 200, 
        'toBeEncrypted' : true,
        'to' : msg.from
    };

    var client = new net.Socket();


    client.connect(PORT, HOST, function() {
        myutil.debug('CONNECTED TO: ' + HOST + ':' + PORT);
        myutil.debug('MESSAGE: ', msg.payload);
        client.write(JSON.stringify(msg.payload));
        client.end();
    });

    client.on('data', function(data) {
        myutil.debug('DATA: (', typeof(data), ') ' + data);
        responseContent += data; // TODO: replace string concatenation here...
        if (data.slice(-TERMINATION_SEQUENCE.length).compare(TERMINATION_SEQUENCE) == 0)
        { // Server's response is terminated.
            client.end()
            response.message = { 'type' : 'PROXY', 'payload' : responseContent };
            callback(response);
        }
    });

    client.on('end', function()
    { // server is closing the connection. Doing so, too.
        myutil.debug('Server is closing the connection. Doing so, too.');
        client.end();
        //response.message = { 'type' : 'PROXY', 'payload' : responseContent };
        //callback(response);
    });

    client.on('timeout', function() {
        myutil.debug('Socket was idle. Closing.');
        client.end(); // destroy?
    });

    client.on('close', function() {
        myutil.debug('Connection closed.');
        response.message = { 'type' : 'PROXY', 'payload' : responseContent };
        callback(response);
    });
}

/**
 * @description Handle a prekey push message.
 * Handle a message from the client who is pushing his prekey(s) to the
 * server. Saves the prekeys to persistent storage and calls the 
 * callback function either with success or an error.
 *
 * @param {Object} msg the message from the client containing the prekey(s)
 * @param {module:main.ResponseCallback} callback the function to call when prekey storage is done or
 *  an error occurred.
 */
function handlePrekeyPush(msg, callback) 
{
    // Key is 32 byte. It is given as Base64 string.
    if (!msg.pk || !msg.pk.kid || !msg.pk.base)
        callback({ 
            'statusCode' : 400, 
            'message' : createErrorObject("ERROR_CODE_PREKEY_PUSH_NONEXISTENT_PREKEY"), 
            'toBeEncrypted' : true,
            'to' : msg.from
        });
    else 
    {
        var re_kid = /^[a-zA-Z0-9\+\/]{11}=$/;  // base64 string of length 12 (8 bytes actually)
        var re_base = /^[a-zA-Z0-9\+\/]{43}=$/; // 32 bytes -> 43 chars base64 and =
        if (!re_kid.test(msg.pk.kid))
            callback({ 
                'statusCode' : 400, 
                'message' : createErrorObject("ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_ID"), 
                'toBeEncrypted' : true,
                'to' : msg.from
            });
        else if (!re_base.test(msg.pk.base))
            callback({ 
                'statusCode' : 400, 
                'message' : createErrorObject("ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_BASE"), 
                'toBeEncrypted' : true,
                'to' : msg.from
            });
        else 
        {
            prekey.put(msg.from, msg.pk.kid, msg.pk.base, function(err)
            {
                if (err) 
                {
                    myutil.debug("Err in handler not null, return 500");
                    callback({ 
                        'statusCode' : 500, 
                        'message' : createErrorObject("ERROR_CODE_PREKEY_PUSH_FAILURE"), 
                        'toBeEncrypted' : true,
                        'to' : msg.from
                    });
                } 
                else
                {
                    callback({
                        'statusCode' : 200,
                        'message' : 'OK',
                        'toBeEncrypted' : true,
                        'to' : msg.from
                    });
                }
            });
        }
    }
}

/**
 * @description Handle a request for a prekey.
 * Handle a message from a client that is asking for another client's prekey.
 * TODO: think about how to limit handing out of prekeys
 *
 * @param {Object} msg the message from the client
 * @param {module:main.ResponseCallback} callback the function to call with the client's
 * prekey or an error.
 */
function handlePrekeyRequest(msg, callback) 
{
    if (!msg.pkreq || !msg.pkreq.id) 
    {
        callback({ 
            'statusCode' : 400, 
            'message' : createErrorObject("ERROR_CODE_PREKEY_GET_ID_NOT_GIVEN"), 
            'toBeEncrypted' : true,
            'to' : msg.from
        });
    } 
    else 
    {
        prekey.get(msg.pkreq.id, function(err, doc) 
        {
            if (err || !doc) 
            {
                prekey.get(LAST_RESORT_KEY_ID, function(err, doc) 
                { // Check if we have a LastResortKey
                    if (err || !doc) 
                    { // Nothing we can do here.
                        callback({ 
                            'statusCode' : 404, 
                            'message' : createErrorObject("ERROR_CODE_PREKEY_GET_NOT_FOUND"), 
                            'toBeEncrypted' : true ,
                            'to' : msg.from
                        });
                    } 
                    else 
                    { // Hand out LastResortKey:
                        callback({ 
                            'statusCode' : 200, 
                            'message' : { 'type' : 'PKHOUT', 'pk' : { 'kid' : doc.key_id , 'base' : doc.base_key } }, 
                            'toBeEncrypted' : true,
                            'to' : msg.from
                        });
                    }
                });
            } 
            else 
            {
                callback({ 
                    'statusCode' : 200, 
                    'message' : { 'type' : 'PKHOUT', 'pk' : { 'kid' : doc.key_id , 'base' : doc.base_key } }, 
                    'toBeEncrypted' : true,
                    'to' : msg.from
                });
            }
        });
    }
}

/**
 * @typedef module:main.Context
 * @type Object
 * @property {Object} request - Node.js request from client
 * @property {Object} response - Node,js response to client
 */

/**
 * @description Respond to a client.
 * Function which is called by the message handlers to respond to 
 * an incoming request by a client. If an error occurred when
 * trying to compute the adequate response this is signalled by
 * an error parameter.
 * Encrypts the response whenever encryption is possible.
 *
 * @param {module:main.Context} context - the context of the request. Contains the request
 *  and the response.
 * @param {module:main.MobileEdgeResponse} response - the actual message to
 *  be sent to the client
 */
function respond(context, response) 
{
    myutil.debug("Status code:", response.statusCode);
    myutil.debug('Sending message:', response.message);
    var text = JSON.stringify(response.message);
    myutil.debug('Sending message text:', text);
    if (response.toBeEncrypted) 
    {
        myutil.debug('Encrypting response.');
        axolotl.sendMessage(response.to, text, function(err, ciphertext, state) {
            if (err) 
            {
                context.response.writeHead(500, {'Content-Type' : 'application/json'});    // 500: internal server error
                context.response.write(createErrorObject("ERROR_CODE_ENCRYPTION_FAILURE"));
            } 
            else 
            {
                context.response.writeHead(response.statusCode, {'Content-Type' : 'application/json'});    // 200: OK
                myutil.debug("YAY:", ciphertext);
                ciphertext.type = "CRYPT";
                context.response.write(JSON.stringify(ciphertext)); // send encrypted
            }
            context.response.end();
        });
    }
    else 
    {
        context.response.writeHead(response.statusCode, {'Content-Type' : 'application/json'});    // 200: OK
        context.response.write(text); // Send unencrypted
        context.response.end();
    }
}

/**
 * @description Given a context (request and response objects, as well as the
 *  received data from the request), dispatches to the adequate handlers for the
 *  message type received. It passes a callback to the handlers that wraps the
 *  context and calls respond() for the given message to send.
 *  
 * @param {module:main.Context} context - the Node.js request and response objects
 * @param {String} data - the data received from the client via the request
 */
function dispatch(context, data) 
{
    function respond_cb(response) 
    {
        respond(context, response);
    }
    try 
    {
        var msg = JSON.parse(data);
    } 
    catch (err) 
    { // not a valid message
        respond_cb({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_INVALID_FORMAT") });
        return;
    }
    switch (msg.type) 
    { // TODO: remove some of these types?
    case 'IDREQ':
        handleIdentityRequest(msg, respond_cb);
        break;
    case 'IDRFS':
        handleIdentityRefresh(msg, respond_cb);
        break;
    case 'KEYXC':
        handleKeyExchange(msg, respond_cb);
        break;
    case 'CRYPT':
        handleEncrypted(msg, respond_cb);
        break;
    default:
        respond_cb({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_INVALID_FORMAT") });
    }
}

/**
 * @description Create the actual HTTPS server. Client requests are handled here, and
 * responses created accordingly.
 *
 * The server expects all messages to have the following format:
 *  { 
 *      "v" :  { ... },
 *      "type" : ... ,
 *      ...
 *  }
 *  
 * The existing message types are: "KEYXC" (key exchange), "CRYPT" (encrypted message).
 * For "CRYPT" the message is expected to have the fields 'head', 'body', and 'from', 
 * Once decrypted and JSON.parse()d, the inner message is expected to have the format:
 *  {
 *      "type" : ... ,
 *      ...
 *  }
 * The types for the decrypted messages are:
 * "IPKPUSH" (initial prekey put/push), "PKREQ" (prekey request).
 * "PKPUSH" (prekey put/push).
 * These messages are expected to have a "pk" and "pkreq" attribute, respectively,
 * which specify the prekey to be pushed or, the id of the user whose
 * prekey is requested.
 */
//var http = require('http');
//var insecureServer = http.createServer(function(request, response) {
var secureServer = https.createServer(sslOptions, function(request, response) 
{
    var body = '';
    request.on('data', function (chunk) 
    {
        body += chunk;
    });
    request.on('end', function () 
    {
        myutil.debug('received request from client', request.headers['user-agent'], '('+body+')',
            'at', request.connection.remoteAddress);
        dispatch({ 'response': response }, body);
    });
}).listen(mainConfig.port, mainConfig.host, function()
{
    myutil.log("Secure server listening on port", mainConfig.port);
    myutil.log("public key:", axolotl.getPublicKey());
});
