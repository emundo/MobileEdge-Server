var expect = require('chai').expect,
    token = require('../libs/token.js'),
    myutil = require('../libs/util.js');

describe('Token Creation', function(){
    describe('#create_id()', function(){
        it('should return an ID token object', function(){
            token.create_id(function(new_token){
                expect(new_token.info, 'property: expires').to.have.property('expires');
                expect(new_token.info, 'property: nonce').to.have.property('nonce').with.length(48);
                expect(new_token.mac, 'mac length').to.have.length(64);
            });
        });
    });
});

describe('Token creation & verification', function(){
    describe('#create_id() & verify_id()', function(){
        it('created token should be valid', function(){
            var new_id;
            token.create_id(function(id) {
                new_id = id; 
            });
            token.verify_id(new_id, function (result) {
                expect(result).to.equal(token.VALID);
            });
           
        });
    });
    describe('# create_id() & refresh_id() & verify_id()', function(){
        it('created token should be able to be refreshed and the result should be valid', function(){
            var old_id, new_id;
            token.create_id(function(id) {
                old_id = id; 
            });
            token.refresh_id(old_id, function(id) {
                new_id = id; 
            });
            token.verify_id(new_id, function (result) {
                expect(result, 'validity').to.equal(token.VALID);
            });
            expect(new_id.info.previous, 'correct reference to old mac').to.equal(old_id.mac);
        });
    });
});
