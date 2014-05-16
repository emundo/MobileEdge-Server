var https = require('https'),
    fs = require('fs');
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
  console.log("Secure Express server listening on port 8888");
});
