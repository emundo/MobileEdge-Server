/**
 * @file Main file of the application. Server is started here.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */
var https = require('https'),
    util = require('util'),
    fs = require('fs');
var token = require("./libs/token.js");
var myutil = require("./libs/util.js");
var sslOptions = {
  key: fs.readFileSync('./ssl/server.key'),
  cert: fs.readFileSync('./ssl/server.crt'),
  ca: fs.readFileSync('./ssl/ca.crt'),
//  requestCert: true,
  rejectUnauthorized: false
};
var secureServer = https.createServer(sslOptions,function(request, response) {
  response.writeHead(200, {"Content-Type": "text/plain"});
  response.write("Hello World");
  response.end();
}).listen('8888', function(){
  myutil.log("Secure server listening on port 8888");
});
