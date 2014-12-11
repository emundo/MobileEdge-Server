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
 * @module main
 * @description Main file of the application. Server is started here.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */

/*
 * Require some important Node modules.
 */
var https = require('https'),
    //nacl_factory = require('js-nacl'),
    net = require('net'),
    util = require('util'),
    fs = require('fs'),
    mongoose = require('mongoose'),
    ds = require('./models/DataSourceMongoose.js');
var DataSource = ds.DataSource;
/**
 * Create a database connection to use globally throughout the program.
 */
global.db_conn = mongoose.connect('mongodb://localhost/keys');

/**
 * Create a global NaCl instance.
 */
//global.nacl = nacl_factory.instantiate();

/*
 * Require our own libraries.
 */
var //token = require("./libs/token.js"),
    myutil = require("./libs/util.js"),
    axolotl = require("./libs/axolotl.js"),
    prekey = require('./libs/prekey.js'),
    errorLib = require('./libs/error.js');

var createErrorObject = errorLib.createErrorObject;
/**
 * The SSL certificates and keys need to be loaded.
 */
var sslOptions = {
  key: fs.readFileSync('./ssl/server.key'),
  cert: fs.readFileSync('./ssl/server.crt'),
  ca: fs.readFileSync('./ssl/ca.crt'),
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
 * @description Handle an identity request from a client.
 * An id token will be generated and passed to a callback which should
 * send the appropriate answer to the client.
 *
 * @param {Object} msg the cleartext identity request message
 * @param {module:main.ResponseCallback} callback the function to call when id generation is done
 */
function handleIdentityRequest(msg, callback) 
{
    token.create_id(function (id_token)
    {
        if (id_token instanceof Error)
            callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_ID_CREATION_FAILURE") });
        else
            callback({ 'statusCode' : 200, 'message' : id_token });
    });
}

/**
 * @description Handle an identity refresh request from a client
 * An id token will be generated that includes the current id of the client
 * for later reference. Calls a callback function with the result or an error.
 *
 * @param {Object} msg the id refresh request msg including the current id
 * @param {module:main.ResponseCallback} callback the function to call when id generation is done
 */
function handleIdentityRefresh(msg, callback) 
{
    if (!msg.id_token)
        callback({ 'statusCode' : 400, 'message' : createErrorObject('ERROR_CODE_REFRESHING_ID_NOT_GIVEN') });
    else 
    {
        token.refresh_id(msg.id_token, function(new_id) 
        {
            if (new_id instanceof Error)
                callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_ID_REFRESHING_FAILURE") });
            else 
                callback({ 'statusCode' : 200, 'message' : new_id });
        });
    }
}

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
                try 
                { // TODO: use domains instead of try/catch!
                    decrypted_msg = JSON.parse(plaintext);
                } 
                catch (err) 
                {
                    callback({ 
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
                receive(msg.from);
            }
            else
            {
                decrypted_msg.from = from;
                receive(from);
            }
        });
    }
    receive(msg.from);
}

function handleProxy(msg, callback)
{
    const HOST = '127.0.0.1';
    const PORT = 6969;
    const TERMINATION_SEQUENCE = new Buffer("\r\n\r\n\r\ngagagag"); 
    var responseContent = "";

    var client = new net.Socket();


    client.connect(PORT, HOST, function() {
        myutil.debug('CONNECTED TO: ' + HOST + ':' + PORT);
        client.write(msg.payload);
        client.end();
    });

    client.on('data', function(data) {
        myutil.debug('DATA: (', typeof(data), ') ' + data);
        responseContent += data; // TODO: replace string concatenation here...
        if (data.slice(-TERMINATION_SEQUENCE.length).compare(TERMINATION_SEQUENCE) == 0)
        { // Server's response is terminated.
            client.end()
            callback({ 
                'statusCode' : 200, 
                'message' : responseContent,
                'toBeEncrypted' : true,
                'to' : msg.from
            });
        }
    });

    client.on('end', function()
    { // server is closing the connection. Doing so, too.
        myutil.debug('Server is closing the connection. Doing so, too.');
        client.end();
        callback({ 
            'statusCode' : 200, 
            'message' : responseContent,
            'toBeEncrypted' : true,
            'to' : msg.from
        });
    });

    client.on('timeout', function() {
        myutil.debug('Socket was idle. Closing.');
        client.end(); // destroy?
    });

    client.on('close', function() {
        console.log('Connection closed.');
        callback({ 
            'statusCode' : 200, 
            'message' : responseContent,
            'toBeEncrypted' : true,
            'to' : msg.from
        });
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
}).listen('8888', function()
{
    myutil.log("Secure server listening on port 8888");
});
