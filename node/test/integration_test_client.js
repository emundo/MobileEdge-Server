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
 * @file Test file for the axolotl protocol.
 * @author Luca Müller <luca.mueller@e-mundo.de>
 */

var https = require('https'),
    expect = require('chai').expect,
    nacl_factory = require('js-nacl'),
    util = require('util'),
    fs = require('fs'),
    myutil = require('../libs/util.js'),
    mongoose = require('mongoose'),
    ds = require('../models/DataSourceMongoose.js');
var AxolotlState = mongoose.model('AxolotlState');

var DataSource = ds.DataSource;
/**
 * Create a database connection to use globally throughout the program.
 */
//global.db_conn = mongoose.connect('mongodb://localhost/keys');

/**
 * Create a global NaCl instance.
 */
global.nacl = nacl_factory.instantiate();

/*
 * Require our own libraries.
 */
var token = require("../libs/token.js"),
myutil = require("../libs/util.js"),
axolotl = require("../libs/axolotl.js");

/**
 * Declare a more meaningful name for crypto_box_keypair in this context.
 */

var newDHParam = nacl.crypto_box_keypair;

/*
Test Client:
1.) get ID token
2.) exchange Keys with Diffie-Hellman
3.) exchange Prekeys

*/


function getOptions(ignoreCert, headers)      //set server IP for testing and CertIgnore
{
    var options = {  
      hostname: '127.0.0.1',
      port: 8888,
      path: '/',
      method: 'GET',
      headers: headers,
      rejectUnauthorized: true,      
      requestCert: true,
      agent: true        
    };    
    
    if (ignoreCert == true) 
    {
        options["rejectUnauthorized"] = false;      //ignore self-signed cert        
        options["agent"] = false;
    }
    
    return options
}

function getHeaders(userString, ClientLevel)   //set headers for https request
{
    var headers = 
    {
      'user-agent': ClientLevel,
      'Content-Type': 'application/json',
      'Content-Length': userString.length
    };
    
    return headers    
}

//                    1.) get ID token

/*
the server accepts this message format:

payload = 
    {
        "type" : "IDREQ"
    };

the response contains an identification token which is used for later communication:

{ info: 
   { expires: 'TTL',
     nonce: 'hex' },
  mac: 'hex' }

*/

function requestID(callback)     
{
    var ID_token;
    var payload = 
    {
        "type" : "IDREQ"
    };

    var userString = JSON.stringify(payload);

    var headers = getHeaders(userString, 'IDRequestClient');   //set Client and build https Headers

    var options = getOptions(true, headers);      //do not ask for certificate validation

    var req = https.request(options, function(res)     //callback at result
    {
        res.on('data', function(d)        //store response content (ID token)
        {
            ID_token = d;
        });
        res.on('end', function () 
        {             
            ID_token = JSON.parse(ID_token);    
            callback(ID_token, res.statusCode);                     //start KeyExchange Routine
        })
    });
    req.end();

    req.on('error', function(e) 
    {
        console.error(e);
    });

    // write data to request body
    req.write(userString);
    req.end();
}

//                        2.) exchange Keys with Diffie-Hellman

/*

the requestID() callback method builds a message for the key exchange procedure (Diffie-Hellman).
The server accepts this message format:
    {
        "type" : "KEYXC",
        "id_token" : ID_token,
        "keys" : aliceKeyExchangeMsg
    };
    
An ID_token is obtained through a previous requestID() call.

The public keys get generated by newDHParam() and their hex values are used to build the message.

The server sends back his on KeyExchange message, which contains an id and two emphemeral keys

{ id: 'xyz',
  eph0: 'xyz',
  eph1: 'xyz' }


The axolotl state is also updated and a test message send

*/

function exchangeKeys(ID_token, callback)   //call requestID() and start KeyExchange Routine at callback
{

    var aliceParams =         //generate Diffie-Hellman Params for KeyExchange
    {
        'id' : newDHParam(),
        'eph0' : newDHParam()   
    } 
    var aliceKeyExchangeMsg =               //build message with public id and ephemeral key
    {
        'id' : myutil.hexToBase64(nacl.to_hex(aliceParams['id']['boxPk'])),
        'eph0' : myutil.hexToBase64(nacl.to_hex(aliceParams['eph0']['boxPk']))
    }     

    var payload = 
    {
        "type" : "KEYXC",
        "id_token" : ID_token,
        "keys" : aliceKeyExchangeMsg
    };  
    
    var userString = JSON.stringify(payload);

    var headers = getHeaders(userString, 'KeyExchangeClient');    //set Client and build https Headers

    var options = getOptions(true, headers);      //do not ask for certificate validation

    var keyExchangeMessage = "";
    
    var req = https.request(options, function(res)    //send KeyExchange message
    {
        res.on('data', function(d)   //get response from Server
        {
            keyExchangeMessage += d;
        });
        res.on('end', function () 
        {            
            keyExchangeMessage = JSON.parse(keyExchangeMessage);          
                              
                       
            var bobID = keyExchangeMessage['id'];
            
            axolotl.keyAgreementAlice(aliceParams, keyExchangeMessage, function(err, keys)    //calculate secret using own Diffie-Hellman params and received
            {
                if (err) 
                {        
                    throw new Error('Apparently Alice could not finish the key agreement.');
                } else 
                {
                    var stateAlice = new AxolotlState();                                 //set up AxolotlState
                    stateAlice.id_mac = bobID;  
                    callback(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice);                
                }
            });        
        })
    });

    req.on('error', function(e) 
    {
        console.error(e);
    });

    // write data to request body
    req.write(userString);
    req.end();
}

/*
                                        3.) exchange Prekeys

when the message type field is omitted the server expects an encrypted message, this message may used to send prekeys

payload = 
        {
            "id_token" : ID_token,
            "payload" : ciphertext
        };

the encrypted message contains a type field and a pk or pkreq field

- PKPUT send prekey, pk
- PKREQ request preky, pkreq

- kid is a nonce 
- base a Diffie-Hellman param 

message = {
                "type" : "PKPUT",
                "pk" : {
                    "kid" : kid,
                    "base" : base
                }
            };

*/


function sendMsg(message, ID_token, bobID, stateAlice, callback)
{
    message = JSON.stringify(message);  
    axolotl.sendMessage(bobID, message, function(err, ciphertext, state) 
    {
        stateAlice = state;     //update state
        
        var result = '';
        
        var payload = 
        {
            "id_token" : ID_token,
            "payload" : ciphertext            //use encrypted message
        };

        var userString = JSON.stringify(payload);
                
        var headers = getHeaders(userString, 'SendMsgClient');      //set Client and build https Headers

        var options = getOptions(true, headers);      //do not ask for certificate validation
        
        var req = https.request(options, function(res) 
        {                   
            res.on('data', function(d) 
            {
                result += d;
            });

            res.on('end', function () 
            {
                result = JSON.parse(result);
                callback(result, bobID);                 //decrpyt the encrpyted response
            });

        });

        req.on('error', function(e) 
        {
            console.error(e);
        });
        // write data to request body
        req.write(userString);
        req.end();
    }, true);
}

function buildPKPUT(ID_token, bobID, callback)
{
    var kid = nacl.to_hex(nacl.crypto_box_random_nonce());
    var base = newDHParam();
    base = nacl.to_hex(base['boxPk']);
    var message = 
    {
        "type" : "PKPUT",
        "pk" : 
        {
            "kid" : kid,
            "base" : base
        }
    };
    
    callback(ID_token, bobID, message);  
}

function buildPKREQ(ID_token, bobID, callback)
{
    var message = 
    {
        "type" : "PKREQ",
        "pkreq" : 
        {
            id_token: ID_token    
        }
    };
    
    callback(ID_token, message, bobID);  
}

function updateStateAlice(keys, keyExchangeMsgBob, aliceParams, ID_token, bobID, stateAlice, callback) 
{
    stateAlice.root_key              = keys.rk;
    stateAlice.chain_key_recv        = keys.ck; // Alice is Client. So we set CKr first.
    stateAlice.header_key_recv       = keys.hk;
    stateAlice.next_header_key_send  = keys.nhk0;
    stateAlice.next_header_key_recv  = keys.nhk1;
    stateAlice.dh_identity_key_send  = nacl.to_hex(aliceParams.id.boxSk);

    stateAlice.dh_identity_key_recv  = myutil.base64ToHex(keyExchangeMsgBob.id);
    stateAlice.dh_ratchet_key_recv   = myutil.base64ToHex(keyExchangeMsgBob.eph1);
//    stateAlice.dh_identity_key_recv  = nacl.to_hex(keyExchangeMsgBob.id);
//    stateAlice.dh_ratchet_key_recv   = nacl.to_hex(keyExchangeMsgBob.eph1);
    stateAlice.counter_send = 0;
    stateAlice.counter_recv = 0;
    stateAlice.previous_counter_send = 0;
    stateAlice.ratchet_flag = true;
    
    AxolotlState.remove({ 'id_mac' : bobID }, function()
    {
        stateAlice.save(function(err) {
            if (!err)
            
            callback(ID_token, bobID);
        });
    });
}

function decryptIncoming(message, bobID, callback) 
{
    axolotl.recvMessage(bobID, message, function (err, plaintext, state) 
    {
        if (err)
            console.log(err);
        else 
        {   
            callback(plaintext);
        }
    });
}

function refreshID(ID_token, callback)     
{
    var new_ID_token;
    var payload = 
    {
        "type" : "IDRFS",
        id_token: ID_token 
    };

    var userString = JSON.stringify(payload);

    var headers = getHeaders(userString, 'IDRefreshClient');   //set Client and build https Headers

    var options = getOptions(true, headers);      //do not ask for certificate validation

    var req = https.request(options, function(res)     //callback at result
    {
        res.on('data', function(d)        
        {
            new_ID_token = d;
        });
        res.on('end', function () 
        {             
            new_ID_token = JSON.parse(new_ID_token);    
            callback(new_ID_token);                    
        })
    });
    req.end();

    req.on('error', function(e) 
    {
        console.error(e);
    });

    // write data to request body
    req.write(userString);
    req.end();
}


describe('requestID', function()
{
  describe('#requestID()', function()
  {
      it('should return Status code 200 and valid ID token', function(done)
      {
        requestID(function (ID_token, statusCode) 
        {                
                expect(ID_token.info, 'property: expires').to.have.property('expires').to.have.length(24);
                expect(ID_token.info, 'property: nonce').to.have.property('nonce').to.have.length(48);
                expect(ID_token, 'property: mac').to.have.property('mac').to.have.length(64);    
                expect(statusCode, 'Status Code').to.equal(200);                
                done();                            
        });        
      });
  });
});

describe('exchangeKeys', function () 
{
    describe('#exchangeKeys()', function()
    {
        it('should return keyExchangeMessage', function(done)
        {
            requestID(function (ID_token, statusCode) 
            {
                exchangeKeys(ID_token, function(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice)
                {

                     expect(keyExchangeMessage, 'property: id').to.have.property('id').to.have.length(32);
                     expect(keyExchangeMessage, 'property: eph0').to.have.property('eph0').to.have.length(32);
                     expect(keyExchangeMessage, 'property: eph1').to.have.property('eph1').to.have.length(32); 
                    
                    done();
                });
            });
        });
    });   
});

describe('updateStateAlice', function () 
{
    describe('#updateStateAlice()', function()
    {
        it('should return ID_token and BobID', function(done)
        {
            requestID(function (ID_token, statusCode) 
            {
                exchangeKeys(ID_token, function(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice)
                {
                    updateStateAlice(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice, function (ID_token, bobID) 
                    {
                        expect(bobID).to.have.length(44);                     
                    done();    
                    });             
                });
            });
        });
    });   
});


describe('buildPKPUT', function () 
{
    describe('#buildPKPUT()', function()
    {
        it('should return PKPUT message', function(done)
        {
            requestID(function (ID_token, statusCode) 
            {
                exchangeKeys(ID_token, function(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice)
                {
                    updateStateAlice(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice, function (ID_token, bobID) 
                    {
                        buildPKPUT(ID_token, bobID, function (ID_token, bobID, message) 
                        {
                            expect(message, 'property: type').to.have.property('type').to.have.length(5);
                            expect(message.pk, 'property: kid').to.have.property('kid').to.have.length(48);
                            expect(message.pk, 'property: base').to.have.property('base').to.have.length(64);  
                            done();     
                        });                   
                    });             
                });
            });
        });
    });   
});

describe('sendMsg', function () 
{
    describe('#sendMsg()', function()
    {
        it('should return server response and bobID', function(done)
        {
            requestID(function (ID_token, statusCode) 
            {
                exchangeKeys(ID_token, function(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice)
                {
                    updateStateAlice(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice, function (ID_token, bobID)  
                    {
                        buildPKPUT(ID_token, bobID, function (ID_token, bobID, message) 
                        {
                            sendMsg(message, ID_token, bobID, stateAlice, function (result, bobID)  
                            {
                                expect(result, 'property: nonce').to.have.property('nonce').to.have.length(48);   
                                expect(result, 'property: head').to.have.property('head').to.have.length(278);    //size changes???  
                                expect(result, 'property: body').to.have.property('body');   
                                done();     
                            })                                 
                        });                   
                    });             
                });
            });
        });
    });   
});

describe('decryptIncoming', function () 
{
    describe('#decryptIncoming()', function()
    {
        it('should return decrypted server message', function(done)
        {
            requestID(function (ID_token, statusCode) 
            {
                exchangeKeys(ID_token, function(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice) 
                {
                    updateStateAlice(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice, function (ID_token, bobID)  
                    {
                        buildPKPUT(ID_token, bobID, function (ID_token, bobID, message) 
                        {
                            sendMsg(message, ID_token, bobID, stateAlice, function (result, bobID) 
                            {
                                decryptIncoming(result, bobID, function (plaintext) 
                                {
                                     expect(plaintext, 'plaintext').to.equal('\"OK\"');  
                                     done(); 
                                 });
                            });                                 
                        });                   
                    });             
                });
            });
        });
    });   
});

describe('buildPKREQ', function () 
{
    describe('#buildPKREQ()', function()
    {
        it('should return PKREQ message', function(done)
        {
            requestID(function (ID_token, statusCode) 
            {
                exchangeKeys(ID_token, function(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice)
                {
                    updateStateAlice(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice, function (ID_token, bobID) 
                    {
                        buildPKREQ(ID_token, bobID, function (ID_token, message, bobID) 
                        {                            
                            expect(message, 'property: type').to.have.property('type').to.have.length(5);
                            expect(message.pkreq.id_token, 'property: mac').to.have.property('mac').to.have.length(64);
                            expect(message.pkreq.id_token.info, 'property: expires').to.have.property('expires').to.have.length(24);
                            expect(message.pkreq.id_token.info, 'property: nonce').to.have.property('nonce').to.have.length(48);                           
                            done();       
                        });                
                    });             
                });
            });
        });
    });   
});

describe('sendPKREQ', function () 
{
    describe('#decryptIncoming()', function()
    {
        it('should return prekey', function(done)
        {
            requestID(function (ID_token, statusCode) 
            {
                exchangeKeys(ID_token, function(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice)
                {
                    updateStateAlice(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice, function (ID_token, bobID) 
                    {
                        buildPKPUT(ID_token, bobID, function (ID_token, bobID, message) 
                        {
                            sendMsg(message, ID_token, bobID, stateAlice, function (result, bobID) 
                            {
                                decryptIncoming(result, bobID, function (plaintext) 
                                {
                                    var tempID_token = ID_token;
                                    requestID(function (ID_token, statusCode) 
                                    {                                        
                                        exchangeKeys(ID_token, function(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice)
                                        {
                                            updateStateAlice(keys, keyExchangeMessage, aliceParams, ID_token, bobID, stateAlice, function (ID_token, bobID) 
                                            {
                                                buildPKREQ(tempID_token, bobID, function (broken_token, message, bobID) 
                                                {                                                    
                                                    sendMsg(message, ID_token, bobID, stateAlice, function (result, bobID)
                                                    {
                                                        decryptIncoming(result, bobID, function (plaintext) 
                                                        {
                                                            plaintext = JSON.parse(plaintext);
                                                            
                                                            expect(plaintext, 'property: type').to.have.property('type').to.have.length(5);
                                                            expect(plaintext.type, 'plaintext').to.equal('PKRET'); 
                                                            expect(plaintext.pk, 'property: kid').to.have.property('kid').to.have.length(48);
                                                            expect(plaintext.pk, 'property: base').to.have.property('base').to.have.length(64);
                                                            done(); 
                                                        });
                                                    });    
                                                }); 
                                            });    
                                        }); 
                                    });
                                });
                            }); 
                        });                   
                    });             
                });
            });
        });
    });   
});



describe('refreshID', function()
{
  describe('#refreshID()', function()
  {
      it('should return a new valid ID token', function(done)
      {
        requestID(function (ID_token, statusCode) 
        {
            refreshID(ID_token, function (new_ID_token) 
            {
                expect(ID_token, 'Status Code').to.not.equal(new_ID_token);                
                expect(new_ID_token.info, 'property: expires').to.have.property('expires').to.have.length(24);
                expect(new_ID_token.info, 'property: nonce').to.have.property('nonce').to.have.length(48);
                expect(new_ID_token, 'property: mac').to.have.property('mac').to.have.length(64);    
                done();                  
            });                    
        });        
      });
  });
});











