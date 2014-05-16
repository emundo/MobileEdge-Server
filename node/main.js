var https = require("https");
var fs = require('fs');

var options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.crt'),
  ca: [fs.readFileSync('cacert.pem')]
};
https.createServer(options, function(request, response) {
  response.writeHead(200, {"Content-Type": "text/plain"});
  response.write("Hello World");
  response.end();
}).listen(8888);
console.log("Server has started.");
