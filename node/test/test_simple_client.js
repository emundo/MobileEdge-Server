var https = require('https'),
    main = require('../main.js'),
    expect = require('chai').expect,
    sodium = require('sodium').api,
    util = require('util'),
    fs = require('fs'),
    myutil = require('../libs/util.js')
    axolotl = require("../libs/axolotl.js"),
    schema = require('../models/schema.js'),
    mongoose = require('mongoose'),
    ds = require('../models/DataSourceMongoose.js');

var AxolotlState = mongoose.model('AxolotlState');
var DataSource = ds.DataSource;

var headers = {
    'user-agent': 'test-client',
    'Content-Type': 'application/json; charset=utf-8'/*,
    'Content-Length': */
};

var options = {  
    hostname: '127.0.0.1',
    port: 8888,
    path: '/',
    method: 'GET',
    headers: headers,
    rejectUnauthorized: false,      
    requestCert: true,
};

function exchangeKeys(callback)
{
    var dsm = new DataSource(),
        state = dsm.axolotl_state.create();
    var aliceParams = {
        'id' : sodium.crypto_box_keypair (),
        'eph0' : sodium.crypto_box_keypair ()
    }
    var aliceKeyExchangeMsg =               //build message with public id and ephemeral key
    {
        'id' : aliceParams.id.publicKey.toString('base64'),
        'eph0' : aliceParams.eph0.publicKey.toString('base64')
    }     
    var keyExchangeOut = 
    {
        "type" : "KEYXC",
        "keys" : aliceKeyExchangeMsg
    };
    function updateStateAlice(keys, keyExchangeIn) {
        state.root_key              = keys.rk;
        state.chain_key_recv        = keys.ck; // Alice is Client. So we set CKr first.
        state.header_key_recv       = keys.hk;
        state.next_header_key_send  = keys.nhk0;
        state.next_header_key_recv  = keys.nhk1;
        state.dh_identity_key_send  = aliceParams.id.secretKey;
        state.dh_identity_key_send_pub  = aliceParams.id.publicKey;
        state.dh_identity_key_recv  = new Buffer(keyExchangeIn.id, 'base64');
        state.dh_ratchet_key_recv   = new Buffer(keyExchangeIn.eph1, 'base64');
        state.counter_send = 0;
        state.counter_recv = 0;
        state.previous_counter_send = 0;
        state.ratchet_flag = true;
        // Alice's state is not a data source, so we need to save this by hand.
        myutil.debug('Header key:', state.next_header_key_send);
        dsm.axolotl_state.save(function (err, state) {
            expect(err).to.not.exist;
            callback(keyExchangeIn.id, aliceParams);
        });
    }
    var jkeyExchangeOut = JSON.stringify(keyExchangeOut);
    options.headers['Content-Length'] = jkeyExchangeOut.length;
    var jkeyExchangeIn = '';
    var keyExchangeIn;
    
    var req = https.request(options, function(res)    //send KeyExchange message
    {
        res.on('data', function(d)   //get response from Server
        {
            jkeyExchangeIn += d;
        });
        res.on('end', function () 
        {            
            keyExchangeIn = JSON.parse(jkeyExchangeIn);          
            axolotl.keyAgreementAlice(aliceParams, keyExchangeIn, function(err, keys)
            {
                if (err) 
                {        
                    throw new Error('Apparently Alice could not finish the key agreement.');
                }
                else 
                {
                    updateStateAlice(keys, keyExchangeIn);
                }
            });        
        });
    });

    req.on('error', function(e) 
    {
        console.error(e);
    });

    myutil.debug('Sending:', jkeyExchangeOut);
    req.write(jkeyExchangeOut);
    req.end();
}

var message = {
    "type" : "PROXY",
    "payload": "Hallo Server!"
};

describe('Simple test client', function()
{
    describe('Key exchange and message', function()
    {
        var aliceParams;
        var bobID;
        it('should encrypt and decrypt messages from the backend', function(done)
        {
            exchangeKeys(function(remoteID, localParams) 
            {
                aliceParams = localParams;
                bobID = remoteID;
                var jMessage = JSON.stringify(message);
                myutil.debug('Encrypting message:', jMessage, 'for', bobID );
                axolotl.sendMessage(bobID, jMessage, function(err, ciphertext, state) 
                {
                    expect(err, 'Error from sending message').to.not.exist;
                    myutil.debug('Encrypted message:', ciphertext);
                    var result = '';
                    ciphertext.type = 'CRYPT';
                    ciphertext.from = aliceParams.id.publicKey.toString('base64');
                    var jPayload = JSON.stringify(ciphertext);
                    options.headers['Content-Length'] = jPayload.length;
                    var req = https.request(options, function(res) 
                    {                   
                        res.on('data', function(d) 
                        {
                            result += d;
                        });
                        res.on('end', function () 
                        {
                            result = JSON.parse(result);
                            myutil.debug('Received answer:', result);
                            axolotl.recvMessage(bobID, result, function(err, plaintext)
                            {
                                expect(err).to.not.exist;
                                myutil.debug('Decrypted message:', plaintext);
                                done();
                            });
                        });
                    });
                    req.on('error', function(e) 
                    {
                        console.error(e);
                    });
                    myutil.debug('Sending message:', jPayload);
                    req.write(jPayload);
                    req.end();
                });
            });
        });
        after (function (done){
            AxolotlState.remove({ 
                    dh_identity_key_recv : new Buffer(aliceParams.id.publicKey, 'base64') 
                }, 
                function()
                {
                });
            AxolotlState.remove({ 
                    dh_identity_key_recv : new Buffer(bobID, 'base64') 
                }, function()
                {
                });
            done();
        });
    });
});

