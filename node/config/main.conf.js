var config = {
    /* 
     * which IP/hostname should the MobileEdge
     * server forward the requests to?
     */
    host : '127.0.0.1',
    /* 
     * on which port is the backend server listening (TCP) 
     */
    port : 8888, 
    /*
     * path to ssl key file:
     */
    serverKey : './ssl/server.key',
    /*
     * path to ssl certificate:
     */
    serverCertificate : './ssl/server.crt',
    /*
     * path to ssl CA certificate:
     */
    CACertificate : './ssl/ca.crt',
};

exports.mainConfiguration = config; 



