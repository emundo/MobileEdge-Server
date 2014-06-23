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
 * @file Main file of the application. Server is started here.
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
    ds = require('./models/DataSourceMongoose.js');

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
 * Handle an identity request from a client.
 * An id token will be generated and passed to a callback which should
 * send the appropriate answer to the client.
 * @param msg the cleartext identity request message
 * @param callback the function to call when id generation is done
 */
function handleIdentityRequest(msg, context, callback) {
    token.create_id(function (id_token){
        if (id_token instanceof Error)
            return callback(500, context, 'Could not create ID.');
        callback(null, context, id_token);
    });
}

/**
 * Handle an identity refresh request from a client
 * An id token will be generated that includes the current id of the client
 * for later reference. Calls a callback function with the result or an error.
 * @param msg the id refresh request msg including the current id
 * @param callback the function to call when id generation is done
 */
function handleIdentityRefresh(msg, context, callback) {
    token.refresh_id(msg.id_token, function(new_id) {
        if (new_id instanceof Error)
            return callback(500, context, 'Could not refresh ID.');
        callback(null, context, new_id);
    });
}

/**
 * Handle a key exchange message from a client.
 * Performs the key exchange using the Axolotl protocol and saves
 * the state to persistent storage.
 * @param msg the client's key exchange message
 * @param callback the function to call when the key agreement finishes
 *  locally. Takes an error or the key exchange message to send to the
 *  client.
 */
function handleKeyExchange(msg, context, callback) {
    token.verify_id(msg.id_token, function(result){
        if (result !== token.VALID)
            return callback(403, context, 'Could not perform key exchange. Token not valid.');
        var theirKeyExchange = {
            'id_mac': msg.id_token.mac,
            'id'    : msg.keys.id,
            'eph0'  : msg.keys.eph0
        };
        axolotl.keyExchange(theirKeyExchange, function(err, ourKeyExchange) {
            if (err) {
                return callback(500, context, 'Could not perform key exchange.');
            }
            callback(null, context, ourKeyExchange);
        });
    });
}

/**
 * Handle any encrypted message that comes from a client.
 * Dispatcher for all encrypted messages that come in. Decrypts them and
 * calls the respective handlers for the specific message type.
 * The message type is determined by looking at the type field
 * of the message, which must contain a valid message type string.
 * @param msg the encrypted message
 * @param callback the function to call when the message has been handled.
 *  This is usually just passed on to the next handler.
 */
function handleEncrypted(msg, context, callback) {
    context.encrypt = true;
    token.verify_id(msg.id_token, function(result) {
        if (result !== token.VALID)
            return callback(403, context, 'Cannot decrypt.'); // 403: Forbidden.
        var dsrc = new DataSource();
        dsrc.axolotl_state.get(msg.id_token.mac, function(err, state) {
            axolotl.recvMessage(state, msg.payload, function(err, plaintext, state) {
                if (err)
                    return callback(500, context, 'Cannot decrypt.');
                try { // TODO: use domains instead of try/catch!
                    decrypted_msg = JSON.parse(plaintext);
                    decrypted_msg.from = msg.id_token.mac;
                    if ('PKPUSH' === decrypted_msg.type)
                        return handlePrekeyPush(decrypted_msg, context, callback);
                    if ('PKREQ' === decrypted_msg.type)
                        return handlePrekeyRequest(decrypted_msg, context, callback);
                    // TODO: handle other message types?
                } catch (err) {
                    callback(400, context, 'Invalid message format.'); // 400: Bad Request
                }
            });
        });
    });
}

/**
 * Handle a prekey push message.
 * Handle a message from the client who is pushing his prekey(s) to the
 * server. Saves the prekeys to persistent storage and calls the 
 * callback function either with success or an error.
 * @param msg the message from the client containing the prekey(s)
 * @param callback the function to call when prekey storage is done or
 *  an error occurred.
 */
function handlePrekeyPush(msg, context, callback) {
    // Key id is random nonce, so 24 byte. * 2 as it is given as hex string
    var re_kid = /[0-9a-f]{48}/;
    var re_base = /[0-9a-f]{64}/;
    if (!re_kid.test(msg.pk.kid))
        return callback(400, context, 'Invalid key id.'); 
    if (!re_base.test(msg.pk.base))
        return callback(400, context, 'Invalid base key.');
    prekey.put(msg.from, msg.pk.kid, msg.pk.base, function(err){
        if (err)
            return callback(500, context, 'Could not store Prekey.');
        callback(null, context, 'OK'); // maybe just callback(null);
    });
}

/**
 * Handle a request for a prekey.
 * Handle a message from a client that is asking for another client's prekey.
 * TODO: think about how to limit handing out of prekeys
 * @param msg the message from the client
 * @param callback the function to call with the client's prekey or an error.
 */
function handlePrekeyRequest(msg, context, callback) {
    prekey.get(msg.pkreq.id_mac, function(err, doc) {
        if (err)
            return callback(404, context, 'Could not find prekey.');
        callback(null, context, { 'kid' : doc.key_id , 'base' : doc.base_key });
    });
}

/**
 * Respond to a client.
 * Function which is called by the message handlers to respond to 
 * an incoming request by a client. If an error occurred when
 * trying to compute the adequate response this is signalled by
 * an error parameter.
 * Encrypts the response whenever encryption is possible.
 * @param err an error, if one occurred.
 * @param context the context of the request. Contains the request
 *  and the response.
 * @param response the actual message to be sent to the client
 */
function respond(err, context, message) {
    if (err) {
        context.response.writeHead(err);
    } else {
        var text = JSON.stringify(message);
        if (context.encrypt) {
            var dsrc = new DataSource();
            dsrc.axolotl_state.get(context.from, function(err, state) {
                axolotl.sendMessage(state, text, function(err, ciphertext, state) {
                    if (err) {
                        context.response.writeHead(500);    // 500: internal server error
                    } else {
                        context.response.writeHead(200);    // 200: OK
                        context.response.write(ciphertext); // send encrypted
                    }
                });
            });
        } else {
            context.response.writeHead(200);    // 200: OK
            context.response.write(text);       // Send unencrypted
        }
    }
    context.response.end();
}

function dispatch(context, data) {
    try { //FIXME: domains
        var msg = JSON.parse(data);
        switch (msg.type) {
        case 'IDREQ':
            return handleIdentityRequest(msg, context, respond);
        case 'IDRFS':
            return handleIdentityRefresh(msg, context, respond);
        case 'KEYXC':
            return handleKeyExchange(msg, context, respond);
        default:
            return handleEncrypted(msg, context, respond);
        }
    } catch (err) { // not a valid message
        context.response.writeHead(400); // 400: Bad Request
        //context.res.write('');
        context.response.end();
    }
}

/**
 * Create the actual HTTPS server. Client requests are handled here, and
 * responses created accordingly.
 */
var secureServer = https.createServer(sslOptions, function(request, response) {
    var body = '';
    request.on('data', function (chunk) {
        body += chunk;
    });
    request.on('end', function () {
        dispatch({ 'response': response }, body)
        /*
        response.writeHead(200, {"Content-Type": "text/plain"});
        response.write("Hello World\n");
        response.write(body + "\n");
        response.end();*/
    });
}).listen('8888', function(){
    myutil.log("Secure server listening on port 8888");
});
