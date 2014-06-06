module.exports = function(grunt) {

    // Project configuration.
    grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    });


    // Default task(s).
    // grunt.registerTask('default', ['uglify']);
    grunt.registerTask('dgeni', 'Generate docs via Dgeni.', function() {
        var dgeni = require('dgeni');
        var done = this.async();

        dgeni.generator('docs/dgeni.conf.js')().then(done);
    });
};
