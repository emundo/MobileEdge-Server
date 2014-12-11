var config = {
    host : '127.0.0.1', // which IP/hostname should the MobileEdge server forward the requests to?
    port : 6969, // on which port is the backend server listening (TCP)
    terminationSeq : new Buffer('\r\n\r\n') // which sequence terminates a response from the backend?
};

exports.proxyConfiguration = config; 
