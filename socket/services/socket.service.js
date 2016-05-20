
/** 
 * This provider handles the handshake to authenticate a user and maintain a secure web socket connection via tokens.
 * It also provides service methods to communicate with the web socket server and set the login and logout url to participating in the authentication.
 * 
 * usage examples:
 * 
 * In the config of the app module:
 * socketServiceProvider.setLoginUrl('/access#/login');
    socketServiceProvider.setLogoutUrl('/access#/login');
 *  
 * In the run of the app module:
 * socketService.connect()
 * 
 * In code controller, directive, service, etc..
 * sockectService.emit or sockectService.on 
 * 
 */
angular
    .module('socketio)
    .service('socketService', socketService);

function socketService($rootScope, $location, $timeout, $q, $window, authService) {

    this.on = on;
    this.emit = emit;
    this.logout = authService.logout;
    this.fetch = fetch;
    this.post = post;
    this.notify = notify;

    ///////////////////

    function on(eventName, callback) {
        authService.connect().then(function (socket) {
            socket.on(eventName, function () {
                var args = arguments;
                $rootScope.$apply(function () {
                    callback.apply(socket, args);
                });
            });
        });
    }

    function emit(eventName, data, callback) {
        authService.connect().then(function (socket) {
            socket.emit(eventName, data, function () {
                var args = arguments;
                $rootScope.$apply(function () {
                    if (callback) {
                        callback.apply(socket, args);
                    }
                });
            });
        });
    }

    /**
     * fetch data the way we call an api 
     * http://stackoverflow.com/questions/20685208/websocket-transport-reliability-socket-io-data-loss-during-reconnection
     * 
     */
    function fetch(operation, data) {
        console.debug('Fetching ' + operation + '...');
        return socketEmit(operation, data)
    }

    /**
     * notify is similar to fetch but more meaningful
     */
    function notify(operation, data) {
        console.debug('Notifying ' + operation + '...');
        return socketEmit(operation, data)
    }

    /**
     * post will handle later on, duplicate record by providing a stamp.
     */
    function post(operation, data) {
        console.debug('Posting ' + operation + '...');
        return socketEmit(operation, data)
    }

    function socketEmit(operation, data) {
        var deferred = $q.defer();
        authService.connect().then(function (socket) {
            // but what if we have not connection before the emit, it will queue call...not so good.
            socket.emit('api', operation, data, function (result) {
                if (result.code) {
                    console.debug('Error on ' + operation + ' ->' + JSON.stringify(result));
                    deferred.reject({ code: result.code, description: result.data })
                }
                else {
                    deferred.resolve(result.data);
                }
            });
        });
        return deferred.promise;
    }
}

