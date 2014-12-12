/*
 * This file is part of MobileEdge-Server, the server-side component
 * of the MobileEdge framework.
 * Copyright (c) 2014 eMundo GmbH

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Created by Raphael Arias on 2014-06-02.
 */

/**
 * @file Test file for the database connection and operations.
 * @author Raphael Arias <raphael.arias@e-mundo.de>
 */
var expect = require('chai').expect,
    main = require('../main.js'),
    token = require('../libs/token.js'),
    myutil = require('../libs/util.js'),
    mongoose = require('mongoose');

var Prekey = mongoose.model('Prekey');
/*
 * The application's database connection.
 */
var conn = global.db_conn;
/*
 * Tests for the database connection.
 */
describe('DB connection', function(){
    /**
     * Test to check the database connection could be established successfully.
     */
    describe('#connect()', function(){
        /**
         * Test that we actually connect to the database and get a
         * mongoose.Mongoose object back.
         */
        it('should connect to the database', function(){
            expect(conn).to.be.an.instanceof(mongoose.Mongoose);
        });
    });
});
/**
 * Tests database writes.
 */
describe('DB write', function(){
    /**
     * Get a Prekey model.
     */
    /**
     * Tests for the save function.
     */
    describe('#save()', function(){
        before(function(done) {
            Prekey.remove({ key_id: 41 }).exec();
            done();
        });
        /**
         * Test the save function returns no error.
         */
        it('should write data to the database', function(done){
            var pk = new Prekey();
            pk.key_id = 41;
            pk.id_mac = 'TESTTEST';
            pk.base_key = 'TESTTEST';
            pk.save(function(err, obj, numAffected) {
                expect(err).to.not.exist;
            });
            done();
        });
        after(function(done){
            Prekey.remove({ key_id: 41 }, done);
        });
    });
    /**
     * Tests for the find() function.
     */
    describe('#find()', function(){
        before(function(done){
            var pk = new Prekey();
            pk.key_id = 27;
            pk.id_mac = 'TESTTEST';
            pk.base_key = 'TESTTEST';
            pk.save(done);
        });
        /**
         * This tests that the data written previously is now 
         * retrievable from the database.
         */
        it('should find previously written test data', function(done){
            var query = Prekey.find( {key_id: 27} );
            expect(query).to.be.an.instanceof(mongoose.Query);
            var promise = query.exec();
            promise.onFulfill(function (arg) {
                expect(arg).to.have.deep.property('[0].base_key', 'TESTTEST');
                done();
            });
        });
        after(function(done){
            Prekey.remove({ key_id: 27 }, done);
        });
    });
    /**
     * Tests for the remove function.
     */
    describe('#remove()', function(){
        /**
         * Test that previously written test data is correctly deleted.
         */
        it('should delete all previously written test data', function(done){
            Prekey.remove({ key_id: 27}).exec();
            var promise = Prekey.find({key_id: 27}).exec();
            promise.onFulfill(function (arg) {
                expect(arg, 'test data prekey id 27').to.be.empty;
                done();
            });
        });
    });
});
