var config = {
    /* 
     * which IP/hostname should the MobileEdge
     * server forward the requests to?
     */
    host : '127.0.0.1',
    /* 
     * on which port is the backend server listening (TCP) 
     */
    port : 6969, 
    /*
     * which sequence terminates a response from the backend?
     */
    terminationSeq : new Buffer('\r\n\r\n') 
};

exports.proxyConfiguration = config; 
