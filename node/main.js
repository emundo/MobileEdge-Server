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
    nacl_factory = require('js-nacl'),
    util = require('util'),
    fs = require('fs'),
    mongoose = require('mongoose'),
    ds = require('./models/DataSourceMongoose.js'),
    prekey = require('./libs/prekey.js'),
    error = require('./libs/error.js');
var createErrorObject = error.createErrorObject;
var DataSource = ds.DataSource;
/**
 * Create a database connection to use globally throughout the program.
 */
global.db_conn = mongoose.connect('mongodb://localhost/keys');

/**
 * Create a global NaCl instance.
 */
global.nacl = nacl_factory.instantiate();

/*
 * Require our own libraries.
 */
var token = require("./libs/token.js"),
    myutil = require("./libs/util.js"),
    axolotl = require("./libs/axolotl.js");

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
function handleIdentityRequest(msg, callback) {
    token.create_id(function (id_token){
        if (id_token instanceof Error)
            callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_ID_CREATION_FAILURE") });
            //callback({ 'statusCode' : 500, 'message' : 'Could not create ID.' });
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
function handleIdentityRefresh(msg, callback) {
    if (!msg.id_token)
        callback({ 'statusCode' : 400, 'message' : createErrorObject('ERROR_CODE_REFRESHING_ID_NOT_GIVEN') });
    else {
        token.refresh_id(msg.id_token, function(new_id) {
            if (new_id instanceof Error)
                callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_ID_REFRESHING_FAILURE") });
                //callback({ 'statusCode' : 500, 'message' : 'Could not refresh ID.' });
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
function handleKeyExchange(msg, callback) {
    if (!msg.id_token)
        callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_KEYEXCHANGE_ID_NOT_GIVEN") });
        //callback({ 'statusCode' : 400, 'message' : 'No ID for key exchange.' });
    else {
        token.verify_id(msg.id_token, function(result){
            if (result !== token.VALID)
                callback({ 'statusCode' : 403, 'message' : createErrorObject("ERROR_CODE_KEYEXCHANGE_ID_INVALID") });
                //callback({ 'statusCode' : 403, 'message' : 'Could not perform key exchange. Invalid ID.' });
            else if (!msg.keys || !msg.keys.id || !msg.keys.eph0)
                callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_KEYEXCHANGE_NO_MESSAGE") });
                //callback({ 'statusCode' : 400, 'message' : 'No key exchange message.' });
            else {
                var theirKeyExchange = {
                    'id_mac': msg.id_token.mac,
                    'id'    : msg.keys.id,
                    'eph0'  : msg.keys.eph0
                };
                axolotl.keyAgreement(theirKeyExchange, function(err, ourKeyExchange) {
                    if (err) {
                callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_KEYEXCHANGE_FAILURE") });
                        //callback({ 'statusCode' : 500, 'message' : 'Could not perform key exchange.' });
                    } else {
                        callback({ 'statusCode' : 200, 'message' : ourKeyExchange });
                    }
                }, true);
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
function handleEncrypted(msg, callback) {
    if (!msg.id_token)
        callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_DECRYPTION_ID_NOT_GIVEN") });
        //callback({ 'statusCode' : 400, 'message' : 'No ID given.' });
    else if (!msg.payload)
        callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_DECRYPTION_NO_MESSAGE") });
        //callback({ 'statusCode' : 400, 'message' : 'No encrypted message.' });
    else {
        token.verify_id(msg.id_token, function(result) {
            if (result !== token.VALID)
                callback({ 'statusCode' : 403, 'message' : createErrorObject("ERROR_CODE_DECRYPTION_ID_INVALID") });
                //callback({ 'statusCode' : 403, 'message' : 'Cannot decrypt. Invalid Token.' });
            else {
                axolotl.recvMessage(msg.id_token.mac, msg.payload, function(err, plaintext, state) {
                    if (err)
                        callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_DECRYPTION_FAILURE") });
                        //callback({ 'statusCode' : 500, 'message' : 'Error while decrypting.' });
                    else {
                        try { // TODO: use domains instead of try/catch!
                            decrypted_msg = JSON.parse(plaintext);
                        } catch (err) {
                            callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_INVALID_INTERNAL_MESSAGE_FORMAT") }); // 400: Bad Request
                            //callback({ 'statusCode' : 400, 'message' : 'Invalid message format.' }); // 400: Bad Request
                        }
                        if (!decrypted_msg.type)
                            callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_INVALID_INTERNAL_MESSAGE_TYPE") }); // 400: Bad Request
                            //callback({ 'statusCode' : 400, 'message' : 'Decrypted message has no type.' }); // 400: Bad Request
                        else {
                            decrypted_msg.from = msg.id_token.mac;
                            if ('PKPUT' === decrypted_msg.type)
                                handlePrekeyPush(decrypted_msg, callback);
                            else if ('PKREQ' === decrypted_msg.type)
                                handlePrekeyRequest(decrypted_msg, callback);
                            // TODO: handle other message types?
                        }
                    }
                });
            }
        });
    }
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
function handlePrekeyPush(msg, callback) {
    // Key id is random nonce, so 24 byte. * 2 as it is given as hex string
    if (!msg.pk || !msg.pk.kid || !msg.pk.base)
        callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_PREKEY_PUSH_NONEXISTENT_PREKEY"), 'toBeEncrypted' : true });
        //callback({ 'statusCode' : 400, 'message' : 'No prekey specified.', 'toBeEncrypted' : true });
    else {
        var re_kid = /[0-9a-f]{48}/;
        var re_base = /[0-9a-f]{64}/;
        if (!re_kid.test(msg.pk.kid))
            callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_ID"), 'toBeEncrypted' : true });
            //callback({ 'statusCode' : 400, 'message' : 'Invalid key id.', 'toBeEncrypted' : true });
        else if (!re_base.test(msg.pk.base))
            callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_PREKEY_PUSH_INVALID_PREKEY_BASE"), 'toBeEncrypted' : true });
            //callback({ 'statusCode' : 400, 'message' : 'Invalid base key.', 'toBeEncrypted' : true });
        else {
            prekey.put(msg.from, msg.pk.kid, msg.pk.base, function(err){
                if (err) {
                    myutil.debug("Err in handler not null, return 500");
                    callback({ 'statusCode' : 500, 'message' : createErrorObject("ERROR_CODE_PREKEY_PUSH_FAILURE"), 'toBeEncrypted' : true });
                    //callback({ 'statusCode' : 500, 'message' : 'Could not store prekey.', 'toBeEncrypted' : true });
                } else {
                    callback({ 'statusCode' : 200, 'message' : 'OK', 'toBeEncrypted' : true });
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
function handlePrekeyRequest(msg, callback) {
    if (!msg.pkreq || !msg.pkreq.id_token) {
        callback({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_PREKEY_GET_ID_NOT_GIVEN"), 'toBeEncrypted' : true });
        //callback({ 'statusCode' : 400, 'message' : 'No identity specified.', 'toBeEncrypted' : true });
    } else {
        token.verify_id(msg.pkreq.id_token, function(result) {
            if (result !== token.VALID) {
                callback({ 'statusCode' : 404, 'message' : createErrorObject("ERROR_CODE_PREKEY_GET_ID_INVALID"), 'toBeEncrypted' : true });
                //callback({ 'statusCode' : 404, 'message' : 'Invalid identity. No prekey present.', 'toBeEncrypted' : true });
            } else {
                prekey.get(msg.pkreq.id_token.mac, function(err, doc) {
                    if (err || !doc) {
                        callback({ 'statusCode' : 404, 'message' : createErrorObject("ERROR_CODE_PREKEY_GET_NOT_FOUND"), 'toBeEncrypted' : true });
                        //callback({ 'statusCode' : 404, 'message' : 'Could not find prekey.', 'toBeEncrypted' : true });
                    } else {
                        callback({ 
                                'statusCode' : 200, 
                                'message' : { 'type' : 'PKRET', 'pk' : { 'kid' : doc.key_id , 'base' : doc.base_key } }, 
                                'toBeEncrypted' : true
                        });
                    }
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
function respond(context, response) {
    myutil.debug("Status code:", response.statusCode);
    myutil.debug('Sending message:', response.message);
    var text = JSON.stringify(response.message);
    if (response.toBeEncrypted) {
        myutil.debug('Encrypting response.');
        axolotl.sendMessage(context.from, text, function(err, ciphertext, state) {
            if (err) {
                context.response.writeHead(500);    // 500: internal server error
                context.response.write(createErrorObject("ERROR_CODE_ENCRYPTION_FAILURE"));
                //context.response.write('Encryption impossible.')
            } else {
                context.response.writeHead(response.statusCode);    // 200: OK
                myutil.debug("YAY:", ciphertext);
                context.response.write(JSON.stringify(ciphertext)); // send encrypted
            }
            context.response.end();
        }, true);
    } else {
        context.response.writeHead(response.statusCode);    // 200: OK
        context.response.write(text);       // Send unencrypted
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
function dispatch(context, data) {
    function respond_cb(response) {
        respond(context, response);
    }
    try {
        var msg = JSON.parse(data);
    } catch (err) { // not a valid message
        respond_cb({ 'statusCode' : 400, 'message' : createErrorObject("ERROR_CODE_INVALID_FORMAT") });
        //respond_cb({ 'statusCode' : 400, 'message' : 'Request did not contain valid JSON.' });
        return;
    }
    if (msg && msg.id_token)
        context.from = msg.id_token.mac;
    switch (msg.type) {
    case 'IDREQ':
        handleIdentityRequest(msg, respond_cb);
        break;
    case 'IDRFS':
        handleIdentityRefresh(msg, respond_cb);
        break;
    case 'KEYXC':
        handleKeyExchange(msg, respond_cb);
        break;
    default:
        handleEncrypted(msg, respond_cb);
    }
}

/**
 * @description Create the actual HTTPS server. Client requests are handled here, and
 * responses created accordingly.
 *
 * The server expects all messages to have the following format:
 *  { 
 *      "type" : ... ,
 *      "id_token" :  { ... },
 *      ...
 *  }
 *  
 * The existing message types are: "IDREQ" (id request), "IDRFS" (id refresh),
 * and "KEYXC" (key exchange).
 * The id_token field may, of course, be omitted (only) in an id request.
 * If a message type is not given, an encrypted message is assumed. Then
 * the message is expected to have the field "payload", which corresponds to the
 * encrypted JSON-encoded "real" message.
 * This message, once decrypted and JSON.parse()d, is expected to have the format:
 *  {
 *      "type" : ... ,
 *      ...
 *  }
 * The types for the decrypted messages are:
 * "PKPUT" (prekey put/push) and "PKREQ" (prekey request).
 * These messages are expected to have a "pk" and "pkreq" attribute, respectively,
 * which specify the prekey to be pushed or, the id of the user whose
 * prekey is requested.
 */
var secureServer = https.createServer(sslOptions, function(request, response) {
    var body = '';
    request.on('data', function (chunk) {
        body += chunk;
    });
    request.on('end', function () {
        dispatch({ 'response': response }, body);
        myutil.debug('received request from client', request.headers['user-agent']);
    });
}).listen('8888', function(){
    myutil.log("Secure server listening on port 8888");
});
