// Karma configuration
// Generated on Wed Aug 05 2015 15:38:51 GMT-0500 (CDT)

module.exports = function (config) {
    config.set({

        // base path that will be used to resolve all patterns (eg. files, exclude)
        basePath: '',

        // set browser inactivity to 120 seconds
        browserNoActivityTimeout: 120000,

        // frameworks to use
        // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
        frameworks: ['jasmine'],

        // list of files / patterns to load in the browser
        files: [
            // currently necessary to make phantomjs with angular 1.5
            './node_modules/phantomjs-polyfill/bind-polyfill.js',

            'libraries/angular/angular.js',
            'libraries/angular-mocks/angular-mocks.js',
            // 'app/bower_components/angular-mocks/angular-mocks.js',    
            //'public/test/assets/socket.io/socket.io-1.3.5.js',
            'socketio/socket.module.js',
            'socketio/**/*.*.js',
            'test/specs/**/*.*.js'
        ],

        // list of files to exclude
        // exclude: [
        //     'public/libraries/**/gulpfile.js',
        //     'public/libraries/**/Gruntfile.js',
        //     'public/build/app-build.js',
        //     'public/build/vendor-build.js'
        // ],

        // preprocess matching files before serving them to the browser
        // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
        preprocessors: {
            // this is necessary since we do not wrap any longer the angular code as it is in the build (in gulp we do it too)
            'dist/**/*.js': ['wrap']
        },

        wrapPreprocessor: {
            // Example: wrap each file in an IIFE
            template: '(function () { <%= contents %> })()'
        },


        // test results reporter to use
        // possible values: 'dots', 'progress'
        // available reporters: https://npmjs.org/browse/keyword/karma-reporter
        reporters: ['dots'],

        // web server port
        port: 9876,

        // enable / disable colors in the output (reporters and logs)
        colors: true,

        // level of logging
        // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
        logLevel: config.LOG_INFO,

        // enable / disable watching file and executing tests whenever any file changes
        autoWatch: true,

        // start these browsers
        // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher

        // uncomment this line when debugging unit tests in Chrome:
        // browsers: ['PhantomJS', 'Chrome'],
        browsers: ['PhantomJS'],

        // Continuous Integration mode
        // if true, Karma captures browsers, runs the tests and exits
        singleRun: false
    });
};
