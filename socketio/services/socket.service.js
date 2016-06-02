
/** 
 * This service allows your application contact the websocket api.
 * 
 * It will ensure that the connection is available and user is authenticated before fetching data.
 * 
 */
angular
    .module('socketio-auth')
    .service('$socketio', socketioService);

function socketioService($rootScope, $q, $auth) {

    this.on = on;
    this.emit = emit;
    this.logout = $auth.logout;
    this.fetch = fetch;
    this.post = post;
    this.notify = notify;

    ///////////////////
    function on(eventName, callback) {
        $auth.connect().then(function (socket) {
            socket.on(eventName, function () {
                var args = arguments;
                $rootScope.$apply(function () {
                    callback.apply(socket, args);
                });
            });
        });
    }
    // deprecated, use post/notify
    function emit(eventName, data, callback) {
        $auth.connect().then(function (socket) {
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
     * post sends data to the server.
     * if data was already submitted, it would just return - which could happen when handling disconnection.
     * 
     * Note:
     *  the code also handles versioning on any posted data
        Ali and Emmanuel decided not to use this solution for now. but I(emmanuel) am not removing the code yet. It does add a version to an object.
     */
    function post(operation, data) {
        console.debug('Posting ' + operation + '...');


        // we do not manage versioning on string, number, date (TODO use lodash)
        if (typeof data === 'string' || data instanceof String ||  data instanceof Date || typeof data === 'number' || typeof data === 'boolean') {
            return socketEmit(operation, data);
        }

        if (!data.version) {
            data.version = -1;
        } else if (data.version > 0) {
            // if positive means we have not increase the version yet
            data.version = -data.version - 1;
        }
        return socketEmit(operation, data)
            .then(function (response) {
                // if success, version is back to positive
                data.version = Math.abs(data.version);
                // the response should have the version too...
                return response;
            })
            .catch(function (err) {
                // if backend has already received this version from this user (token)...
                if (err.code == 'ALREADY_SUBMITTED') {
                    data.version = Math.abs(data.version);
                    return $q.resolve(data);
                } else {
                    return $q.reject(err);
                }

            })
    }

    function socketEmit(operation, data) {

        return $auth.connect()
            .then(onConnectionSuccess, onConnectionError)
            ;// .catch(onConnectionError);

        ////////////
        function onConnectionSuccess(socket) {
            // but what if we have not connection before the emit, it will queue call...not so good.        
            var deferred = $q.defer();
            socket.emit('api', operation, data, function (result) {
                if (result.code) {
                    console.debug('Error on ' + operation + ' ->' + JSON.stringify(result));
                    deferred.reject({ code: result.code, description: result.data });
                }
                else {
                    deferred.resolve(result.data);
                }
            });
            return deferred.promise;
        }

        function onConnectionError(err) {
            return $q.reject({ code: 'CONNECTION_ERR', description: err });
        }
    }
}

