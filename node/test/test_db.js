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
 * @file Test file for the database connection and operations.
 */
var expect = require('chai').expect,
    main = require('../main.js'),
    token = require('../libs/token.js'),
    myutil = require('../libs/util.js'),
    mongoose = require('mongoose');

var conn = global.db_conn;
describe('DB connection', function(){
describe('#connect()', function(){
    it('should connect to the database', function(){
            expect(conn).to.be.an.instanceof(mongoose.Mongoose);
        });
    });
});
describe('DB write', function(){
    var Prekey = mongoose.model('Prekey');
    describe('#save()', function(){
        it('should write data to the database', function(){
            var pk = new Prekey();
            pk.key_id = 27;
            pk.base_key = 'TESTTEST';
            pk.save(function(err, obj, numAffected) {
                expect(err).to.not.exist;
            });
        });
    });
    describe('#find()', function(){
        it('should find previously written test data', function(){
            var query = Prekey.find( {key_id: 27} );
            expect(query).to.be.an.instanceof(mongoose.Query);
            var promise = query.exec();
            promise.onFulfill(function (arg) {
                expect(arg).to.have.deep.property('[0].base_key', 'TESTTEST');
            });
        });
    });
    describe('#remove()', function(){
        it('should delete all previously written test data', function(){
            Prekey.remove({ key_id: 27}).exec();
            var promise = Prekey.find({key_id: 27}).exec();
            promise.onFulfill(function (arg) {
                expect(arg).to.be.empty;
            });
        });
    });
});
