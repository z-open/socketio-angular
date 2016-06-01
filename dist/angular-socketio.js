(function() {
"use strict";

angular.module('socketio-auth', []);
}());

(function() {
"use strict";

/** 
 * This provider handles the handshake to authenticate a user and maintain a secure web socket connection via tokens.
 * It also sets the login and logout url participating in the authentication.
 * 
 * 
 * usage examples:
 * 
 * In the config of the app module:
 * socketServiceProvider.setLoginUrl('/access#/login');
 * socketServiceProvider.setLogoutUrl('/access#/login');
 * socketServiceProvider.setReconnectionMaxTimeInSecs(15);
 * This defines how much time we can wait to establish a successul connection before rejecting the connection (socketService.connectIO) with a timeout. by default, it will try for 15 seconds to get a connection and then give up
 *  
 * Before any socket use in your services or resolve blocks, connect() makes sure that we have an established authenticated connection by using the following:
 * socketService.connect().then(
 * function(socket){ ... socket.emit().. }).catch(function(err) {...})
 * 
 * 
 */
angular
    .module('socketio-auth')
    .provider('$auth', authProvider);

function authProvider() {

    var loginUrl, logoutUrl, reconnectionMaxTime = 15;

    this.setLoginUrl = function (value) {
        loginUrl = value;
    };

    this.setLogoutUrl = function (value) {
        logoutUrl = value;
    };

    this.setReconnectionMaxTimeInSecs = function (value) {
        reconnectionMaxTime = value * 1000;
    };

    this.$get = ["$rootScope", "$location", "$timeout", "$q", "$window", function ($rootScope, $location, $timeout, $q, $window) {

        var socket;
        var userToken = retrieveToken();
        var sessionUser = {};
        $rootScope.sessionUser = sessionUser;

        if (!userToken) {
            // @TODO: this right way to redirect if we have no token when we refresh or hit the app.
            //  redirect(loginUrl);
            // but it would prevent most unit tests from running because this module is tighly coupled with all unit tests (depends on it)at this time :

        } else {
            localStorage.token = userToken;
        }
        return {
            connect: connect,
            logout: logout
        };

        ///////////////////
        /**
         * returns a promise 
         * the success function receives the socket as a parameter
         */
        function connect() {
            if (!socket) {
                setup();
            }
            return getForValidConnection();
        }

        function logout() {
            // connection could be lost during logout..so it could mean we have not logout on server side.
            if (socket) {
                socket.emit('logout', userToken);
            }
        }

        function getForValidConnection() {
            var deferred = $q.defer();
            if (sessionUser.connected) {
                deferred.resolve(socket);
            } else {
                // being the scene, socket.io is trying to reconnect and authenticate if the connection was lost;
                reconnect().then(function () {
                    deferred.resolve(socket);
                }).catch(function (err) {
                    deferred.reject('USER_NOT_CONNECTED');
                });
            }
            return deferred.promise;
        }

        function reconnect() {
            var deferred = $q.defer();

            if (sessionUser.connected) {
                deferred.resolve(socket);
            }
            //@TODO TO THINK ABOUT:, if the socket is connecting already, means that a connect was called already by another async call, so just wait for user_connected
            
            
            
            // if the response does not come quick..let's give up so we don't get stuck waiting
            // @TODO:other way is to watch for a connection error...
            var acceptableDelay;
            var off = $rootScope.$on('user_connected', function () {
                off();
                if (acceptableDelay) {
                    $timeout.cancel(acceptableDelay);
                }
                deferred.resolve(socket);
            });

            acceptableDelay = $timeout(function () {
                off();
                deferred.reject('TIMEOUT');
            }, reconnectionMaxTime);

            return deferred.promise;
        }

        function setup() {
            if (socket) {
                //already called...
                return;
            }
            var tokenValidityTimeout;
            // establish connection without passing the token (so that it is not visible in the log)
            socket = io.connect({
                'forceNew': true,
            });

            socket
                .on('connect', onConnect)
                .on('authenticated', onAuthenticated)
                .on('unauthorized', onUnauthorized)
                .on('logged_out', onLogOut)
                .on('disconnect', onDisconnect);

            // TODO: this followowing event is still used.???....
            socket
                .on('connect_error', function () {
                    setConnectionStatus(false);
                });

            /////////////////////////////////////////////
            function onConnect() {
                // the socket is connected, time to pass the token to authenticate asap
                // because the token is about to expire...if it expires we will have to relog in
                setConnectionStatus(false);
                socket.emit('authenticate', { token: userToken }); // send the jwt
            }

            function onDisconnect() {
                console.debug('Session disconnected');
                setConnectionStatus(false);
            }

            function onAuthenticated(refreshToken) {
                clearTokenTimeout();
                // the server confirmed that the token is valid...we are good to go
                console.debug('authenticated, received new token: ' + (refreshToken != userToken));
                localStorage.token = refreshToken;
                userToken = refreshToken;
                setLoginUser(userToken);
                setConnectionStatus(true);
                requestNewTokenBeforeExpiration(userToken);
                $rootScope.$broadcast('user_connected');
            }

            function onLogOut() {
                clearTokenTimeout();
                // token is no longer available.
                delete localStorage.token;
                setConnectionStatus(false);
                redirect(logoutUrl || loginUrl);
            }

            function onUnauthorized(msg) {
                clearTokenTimeout();
                console.debug('unauthorized: ' + JSON.stringify(msg.data));
                setConnectionStatus(false);
                redirect(loginUrl);
            }

            function setConnectionStatus(connected) {
                sessionUser.connected = connected;
                //console.debug("Connection status:" + JSON.stringify(sessionUser));
            }

            function setLoginUser(token) {
                var payload = decode(token);
                sessionUser.id = payload.id;
                sessionUser.display = payload.display;
                sessionUser.firstName = payload.firstName;
                sessionUser.lastName = payload.lastName;
                sessionUser.role = payload.role;
            }

            function clearTokenTimeout() {
                if (tokenValidityTimeout) {
                    $timeout.cancel(tokenValidityTimeout);
                }
            }

            function decode(token) {
                var base64Url = token.split('.')[1];
                var base64 = base64Url.replace('-', '+').replace('_', '/');
                var payload = JSON.parse($window.atob(base64));
                return payload;
            }

            function requestNewTokenBeforeExpiration(token) {
                // request a little before...
                var payload = decode(token, { complete: false });

                var initial = payload.dur;

                var duration = (initial * 90 / 100) | 0;
                console.debug('Schedule to request a new token in ' + duration + ' seconds (token duration:' + initial + ')');
                tokenValidityTimeout = $timeout(function () {
                    console.debug('Time to request new token ' + initial);
                    socket.emit('authenticate', { token: token });
                    // Note: If communication crashes right after we emitted and when servers is sending back the token,
                    // when the client reestablishes the connection, we would have to login because the previous token would be invalidated.
                }, duration * 1000);
            }
        }

        function retrieveToken() {
            var userToken = $location.search().token;
            if (userToken) {
                console.debug('Using token passed during redirection: ' + userToken);
            } else {
                userToken = localStorage.token;
                if (userToken) {
                    console.debug('Using Token in local storage: ' + userToken);
                } else {

                }
            }
            return userToken;
        }

        function redirect(url) {
            window.location.replace(url || 'badUrl.html');
        }
    }];
}
}());

(function() {
"use strict";

/** 
 * This service allows your application contact the websocket api.
 * 
 * It will ensure that the connection is available and user is authenticated before fetching data.
 * 
 */
socketioService.$inject = ["$rootScope", "$q", "$auth"];
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
}());


//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFuZ3VsYXItc29ja2V0aW8uanMiLCIvc291cmNlL3NvY2tldC5tb2R1bGUuanMiLCIvc291cmNlL3NlcnZpY2VzL2F1dGguc2VydmljZS5qcyIsIi9zb3VyY2Uvc2VydmljZXMvc29ja2V0LnNlcnZpY2UuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsQ0FBQyxXQUFXO0FBQ1o7O0FDREEsUUFBQSxPQUFBLGlCQUFBOzs7QURNQSxDQUFDLFdBQVc7QUFDWjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FFYUE7S0FDQSxPQUFBO0tBQ0EsU0FBQSxTQUFBOztBQUVBLFNBQUEsZUFBQTs7SUFFQSxJQUFBLFVBQUEsV0FBQSxzQkFBQTs7SUFFQSxLQUFBLGNBQUEsVUFBQSxPQUFBO1FBQ0EsV0FBQTs7O0lBR0EsS0FBQSxlQUFBLFVBQUEsT0FBQTtRQUNBLFlBQUE7OztJQUdBLEtBQUEsK0JBQUEsVUFBQSxPQUFBO1FBQ0Esc0JBQUEsUUFBQTs7O0lBR0EsS0FBQSxnRUFBQSxVQUFBLFlBQUEsV0FBQSxVQUFBLElBQUEsU0FBQTs7UUFFQSxJQUFBO1FBQ0EsSUFBQSxZQUFBO1FBQ0EsSUFBQSxjQUFBO1FBQ0EsV0FBQSxjQUFBOztRQUVBLElBQUEsQ0FBQSxXQUFBOzs7OztlQUtBO1lBQ0EsYUFBQSxRQUFBOztRQUVBLE9BQUE7WUFDQSxTQUFBO1lBQ0EsUUFBQTs7Ozs7Ozs7UUFRQSxTQUFBLFVBQUE7WUFDQSxJQUFBLENBQUEsUUFBQTtnQkFDQTs7WUFFQSxPQUFBOzs7UUFHQSxTQUFBLFNBQUE7O1lBRUEsSUFBQSxRQUFBO2dCQUNBLE9BQUEsS0FBQSxVQUFBOzs7O1FBSUEsU0FBQSx3QkFBQTtZQUNBLElBQUEsV0FBQSxHQUFBO1lBQ0EsSUFBQSxZQUFBLFdBQUE7Z0JBQ0EsU0FBQSxRQUFBO21CQUNBOztnQkFFQSxZQUFBLEtBQUEsWUFBQTtvQkFDQSxTQUFBLFFBQUE7bUJBQ0EsTUFBQSxVQUFBLEtBQUE7b0JBQ0EsU0FBQSxPQUFBOzs7WUFHQSxP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LE9BQUE7O0lBRUEsS0FBQSxLQUFBO0lBQ0EsS0FBQSxPQUFBO0lBQ0EsS0FBQSxTQUFBLE1BQUE7SUFDQSxLQUFBLFFBQUE7SUFDQSxLQUFBLE9BQUE7SUFDQSxLQUFBLFNBQUE7OztJQUdBLFNBQUEsR0FBQSxXQUFBLFVBQUE7UUFDQSxNQUFBLFVBQUEsS0FBQSxVQUFBLFFBQUE7WUFDQSxPQUFBLEdBQUEsV0FBQSxZQUFBO2dCQUNBLElBQUEsT0FBQTtnQkFDQSxXQUFBLE9BQUEsWUFBQTtvQkFDQSxTQUFBLE1BQUEsUUFBQTs7Ozs7O0lBTUEsU0FBQSxLQUFBLFdBQUEsTUFBQSxVQUFBO1FBQ0EsTUFBQSxVQUFBLEtBQUEsVUFBQSxRQUFBO1lBQ0EsT0FBQSxLQUFBLFdBQUEsTUFBQSxZQUFBO2dCQUNBLElBQUEsT0FBQTtnQkFDQSxXQUFBLE9BQUEsWUFBQTtvQkFDQSxJQUFBLFVBQUE7d0JBQ0EsU0FBQSxNQUFBLFFBQUE7Ozs7Ozs7Ozs7OztJQVlBLFNBQUEsTUFBQSxXQUFBLE1BQUE7UUFDQSxRQUFBLE1BQUEsY0FBQSxZQUFBO1FBQ0EsT0FBQSxXQUFBLFdBQUE7Ozs7OztJQU1BLFNBQUEsT0FBQSxXQUFBLE1BQUE7UUFDQSxRQUFBLE1BQUEsZUFBQSxZQUFBO1FBQ0EsT0FBQSxXQUFBLFdBQUE7Ozs7Ozs7Ozs7O0lBV0EsU0FBQSxLQUFBLFdBQUEsTUFBQTtRQUNBLFFBQUEsTUFBQSxhQUFBLFlBQUE7Ozs7UUFJQSxJQUFBLE9BQUEsU0FBQSxZQUFBLGdCQUFBLFdBQUEsZ0JBQUEsUUFBQSxPQUFBLFNBQUEsWUFBQSxPQUFBLFNBQUEsV0FBQTtZQUNBLE9BQUEsV0FBQSxXQUFBOzs7UUFHQSxJQUFBLENBQUEsS0FBQSxTQUFBO1lBQ0EsS0FBQSxVQUFBLENBQUE7ZUFDQSxJQUFBLEtBQUEsVUFBQSxHQUFBOztZQUVBLEtBQUEsVUFBQSxDQUFBLEtBQUEsVUFBQTs7UUFFQSxPQUFBLFdBQUEsV0FBQTthQUNBLEtBQUEsVUFBQSxVQUFBOztnQkFFQSxLQUFBLFVBQUEsS0FBQSxJQUFBLEtBQUE7O2dCQUVBLE9BQUE7O2FBRUEsTUFBQSxVQUFBLEtBQUE7O2dCQUVBLElBQUEsSUFBQSxRQUFBLHFCQUFBO29CQUNBLEtBQUEsVUFBQSxLQUFBLElBQUEsS0FBQTtvQkFDQSxPQUFBLEdBQUEsUUFBQTt1QkFDQTtvQkFDQSxPQUFBLEdBQUEsT0FBQTs7Ozs7O0lBTUEsU0FBQSxXQUFBLFdBQUEsTUFBQTs7UUFFQSxPQUFBLE1BQUE7YUFDQSxLQUFBLHFCQUFBOzs7O1FBSUEsU0FBQSxvQkFBQSxRQUFBOztZQUVBLElBQUEsV0FBQSxHQUFBO1lBQ0EsT0FBQSxLQUFBLE9BQUEsV0FBQSxNQUFBLFVBQUEsUUFBQTtnQkFDQSxJQUFBLE9BQUEsTUFBQTtvQkFDQSxRQUFBLE1BQUEsY0FBQSxZQUFBLFFBQUEsS0FBQSxVQUFBO29CQUNBLFNBQUEsT0FBQSxFQUFBLE1BQUEsT0FBQSxNQUFBLGFBQUEsT0FBQTs7cUJBRUE7b0JBQ0EsU0FBQSxRQUFBLE9BQUE7OztZQUdBLE9BQUEsU0FBQTs7O1FBR0EsU0FBQSxrQkFBQSxLQUFBO1lBQ0EsT0FBQSxHQUFBLE9BQUEsRUFBQSxNQUFBLGtCQUFBLGFBQUE7Ozs7OztBSDZRQSIsImZpbGUiOiJhbmd1bGFyLXNvY2tldGlvLmpzIiwic291cmNlc0NvbnRlbnQiOlsiKGZ1bmN0aW9uKCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbmFuZ3VsYXIubW9kdWxlKCdzb2NrZXRpby1hdXRoJywgW10pO1xufSgpKTtcblxuKGZ1bmN0aW9uKCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbi8qKiBcbiAqIFRoaXMgcHJvdmlkZXIgaGFuZGxlcyB0aGUgaGFuZHNoYWtlIHRvIGF1dGhlbnRpY2F0ZSBhIHVzZXIgYW5kIG1haW50YWluIGEgc2VjdXJlIHdlYiBzb2NrZXQgY29ubmVjdGlvbiB2aWEgdG9rZW5zLlxuICogSXQgYWxzbyBzZXRzIHRoZSBsb2dpbiBhbmQgbG9nb3V0IHVybCBwYXJ0aWNpcGF0aW5nIGluIHRoZSBhdXRoZW50aWNhdGlvbi5cbiAqIFxuICogXG4gKiB1c2FnZSBleGFtcGxlczpcbiAqIFxuICogSW4gdGhlIGNvbmZpZyBvZiB0aGUgYXBwIG1vZHVsZTpcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRMb2dpblVybCgnL2FjY2VzcyMvbG9naW4nKTtcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRMb2dvdXRVcmwoJy9hY2Nlc3MjL2xvZ2luJyk7XG4gKiBzb2NrZXRTZXJ2aWNlUHJvdmlkZXIuc2V0UmVjb25uZWN0aW9uTWF4VGltZUluU2VjcygxNSk7XG4gKiBUaGlzIGRlZmluZXMgaG93IG11Y2ggdGltZSB3ZSBjYW4gd2FpdCB0byBlc3RhYmxpc2ggYSBzdWNjZXNzdWwgY29ubmVjdGlvbiBiZWZvcmUgcmVqZWN0aW5nIHRoZSBjb25uZWN0aW9uIChzb2NrZXRTZXJ2aWNlLmNvbm5lY3RJTykgd2l0aCBhIHRpbWVvdXQuIGJ5IGRlZmF1bHQsIGl0IHdpbGwgdHJ5IGZvciAxNSBzZWNvbmRzIHRvIGdldCBhIGNvbm5lY3Rpb24gYW5kIHRoZW4gZ2l2ZSB1cFxuICogIFxuICogQmVmb3JlIGFueSBzb2NrZXQgdXNlIGluIHlvdXIgc2VydmljZXMgb3IgcmVzb2x2ZSBibG9ja3MsIGNvbm5lY3QoKSBtYWtlcyBzdXJlIHRoYXQgd2UgaGF2ZSBhbiBlc3RhYmxpc2hlZCBhdXRoZW50aWNhdGVkIGNvbm5lY3Rpb24gYnkgdXNpbmcgdGhlIGZvbGxvd2luZzpcbiAqIHNvY2tldFNlcnZpY2UuY29ubmVjdCgpLnRoZW4oXG4gKiBmdW5jdGlvbihzb2NrZXQpeyAuLi4gc29ja2V0LmVtaXQoKS4uIH0pLmNhdGNoKGZ1bmN0aW9uKGVycikgey4uLn0pXG4gKiBcbiAqIFxuICovXG5hbmd1bGFyXG4gICAgLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcpXG4gICAgLnByb3ZpZGVyKCckYXV0aCcsIGF1dGhQcm92aWRlcik7XG5cbmZ1bmN0aW9uIGF1dGhQcm92aWRlcigpIHtcblxuICAgIHZhciBsb2dpblVybCwgbG9nb3V0VXJsLCByZWNvbm5lY3Rpb25NYXhUaW1lID0gMTU7XG5cbiAgICB0aGlzLnNldExvZ2luVXJsID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgIGxvZ2luVXJsID0gdmFsdWU7XG4gICAgfTtcblxuICAgIHRoaXMuc2V0TG9nb3V0VXJsID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgIGxvZ291dFVybCA9IHZhbHVlO1xuICAgIH07XG5cbiAgICB0aGlzLnNldFJlY29ubmVjdGlvbk1heFRpbWVJblNlY3MgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgcmVjb25uZWN0aW9uTWF4VGltZSA9IHZhbHVlICogMTAwMDtcbiAgICB9O1xuXG4gICAgdGhpcy4kZ2V0ID0gZnVuY3Rpb24gKCRyb290U2NvcGUsICRsb2NhdGlvbiwgJHRpbWVvdXQsICRxLCAkd2luZG93KSB7XG5cbiAgICAgICAgdmFyIHNvY2tldDtcbiAgICAgICAgdmFyIHVzZXJUb2tlbiA9IHJldHJpZXZlVG9rZW4oKTtcbiAgICAgICAgdmFyIHNlc3Npb25Vc2VyID0ge307XG4gICAgICAgICRyb290U2NvcGUuc2Vzc2lvblVzZXIgPSBzZXNzaW9uVXNlcjtcblxuICAgICAgICBpZiAoIXVzZXJUb2tlbikge1xuICAgICAgICAgICAgLy8gQFRPRE86IHRoaXMgcmlnaHQgd2F5IHRvIHJlZGlyZWN0IGlmIHdlIGhhdmUgbm8gdG9rZW4gd2hlbiB3ZSByZWZyZXNoIG9yIGhpdCB0aGUgYXBwLlxuICAgICAgICAgICAgLy8gIHJlZGlyZWN0KGxvZ2luVXJsKTtcbiAgICAgICAgICAgIC8vIGJ1dCBpdCB3b3VsZCBwcmV2ZW50IG1vc3QgdW5pdCB0ZXN0cyBmcm9tIHJ1bm5pbmcgYmVjYXVzZSB0aGlzIG1vZHVsZSBpcyB0aWdobHkgY291cGxlZCB3aXRoIGFsbCB1bml0IHRlc3RzIChkZXBlbmRzIG9uIGl0KWF0IHRoaXMgdGltZSA6XG5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGxvY2FsU3RvcmFnZS50b2tlbiA9IHVzZXJUb2tlbjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgY29ubmVjdDogY29ubmVjdCxcbiAgICAgICAgICAgIGxvZ291dDogbG9nb3V0XG4gICAgICAgIH07XG5cbiAgICAgICAgLy8vLy8vLy8vLy8vLy8vLy8vL1xuICAgICAgICAvKipcbiAgICAgICAgICogcmV0dXJucyBhIHByb21pc2UgXG4gICAgICAgICAqIHRoZSBzdWNjZXNzIGZ1bmN0aW9uIHJlY2VpdmVzIHRoZSBzb2NrZXQgYXMgYSBwYXJhbWV0ZXJcbiAgICAgICAgICovXG4gICAgICAgIGZ1bmN0aW9uIGNvbm5lY3QoKSB7XG4gICAgICAgICAgICBpZiAoIXNvY2tldCkge1xuICAgICAgICAgICAgICAgIHNldHVwKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZ2V0Rm9yVmFsaWRDb25uZWN0aW9uKCk7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICAgICAgICAvLyBjb25uZWN0aW9uIGNvdWxkIGJlIGxvc3QgZHVyaW5nIGxvZ291dC4uc28gaXQgY291bGQgbWVhbiB3ZSBoYXZlIG5vdCBsb2dvdXQgb24gc2VydmVyIHNpZGUuXG4gICAgICAgICAgICBpZiAoc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2xvZ291dCcsIHVzZXJUb2tlbik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBnZXRGb3JWYWxpZENvbm5lY3Rpb24oKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuICAgICAgICAgICAgaWYgKHNlc3Npb25Vc2VyLmNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgLy8gYmVpbmcgdGhlIHNjZW5lLCBzb2NrZXQuaW8gaXMgdHJ5aW5nIHRvIHJlY29ubmVjdCBhbmQgYXV0aGVudGljYXRlIGlmIHRoZSBjb25uZWN0aW9uIHdhcyBsb3N0O1xuICAgICAgICAgICAgICAgIHJlY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHNvY2tldCk7XG4gICAgICAgICAgICAgICAgfSkuY2F0Y2goZnVuY3Rpb24gKGVycikge1xuICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoJ1VTRVJfTk9UX0NPTk5FQ1RFRCcpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZWNvbm5lY3QoKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgICBpZiAoc2Vzc2lvblVzZXIuY29ubmVjdGVkKSB7XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy9AVE9ETyBUTyBUSElOSyBBQk9VVDosIGlmIHRoZSBzb2NrZXQgaXMgY29ubmVjdGluZyBhbHJlYWR5LCBtZWFucyB0aGF0IGEgY29ubmVjdCB3YXMgY2FsbGVkIGFscmVhZHkgYnkgYW5vdGhlciBhc3luYyBjYWxsLCBzbyBqdXN0IHdhaXQgZm9yIHVzZXJfY29ubmVjdGVkXG4gICAgICAgICAgICBcbiAgICAgICAgICAgIFxuICAgICAgICAgICAgXG4gICAgICAgICAgICAvLyBpZiB0aGUgcmVzcG9uc2UgZG9lcyBub3QgY29tZSBxdWljay4ubGV0J3MgZ2l2ZSB1cCBzbyB3ZSBkb24ndCBnZXQgc3R1Y2sgd2FpdGluZ1xuICAgICAgICAgICAgLy8gQFRPRE86b3RoZXIgd2F5IGlzIHRvIHdhdGNoIGZvciBhIGNvbm5lY3Rpb24gZXJyb3IuLi5cbiAgICAgICAgICAgIHZhciBhY2NlcHRhYmxlRGVsYXk7XG4gICAgICAgICAgICB2YXIgb2ZmID0gJHJvb3RTY29wZS4kb24oJ3VzZXJfY29ubmVjdGVkJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIG9mZigpO1xuICAgICAgICAgICAgICAgIGlmIChhY2NlcHRhYmxlRGVsYXkpIHtcbiAgICAgICAgICAgICAgICAgICAgJHRpbWVvdXQuY2FuY2VsKGFjY2VwdGFibGVEZWxheSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICBhY2NlcHRhYmxlRGVsYXkgPSAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgb2ZmKCk7XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KCdUSU1FT1VUJyk7XG4gICAgICAgICAgICB9LCByZWNvbm5lY3Rpb25NYXhUaW1lKTtcblxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBzZXR1cCgpIHtcbiAgICAgICAgICAgIGlmIChzb2NrZXQpIHtcbiAgICAgICAgICAgICAgICAvL2FscmVhZHkgY2FsbGVkLi4uXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdmFyIHRva2VuVmFsaWRpdHlUaW1lb3V0O1xuICAgICAgICAgICAgLy8gZXN0YWJsaXNoIGNvbm5lY3Rpb24gd2l0aG91dCBwYXNzaW5nIHRoZSB0b2tlbiAoc28gdGhhdCBpdCBpcyBub3QgdmlzaWJsZSBpbiB0aGUgbG9nKVxuICAgICAgICAgICAgc29ja2V0ID0gaW8uY29ubmVjdCh7XG4gICAgICAgICAgICAgICAgJ2ZvcmNlTmV3JzogdHJ1ZSxcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICBzb2NrZXRcbiAgICAgICAgICAgICAgICAub24oJ2Nvbm5lY3QnLCBvbkNvbm5lY3QpXG4gICAgICAgICAgICAgICAgLm9uKCdhdXRoZW50aWNhdGVkJywgb25BdXRoZW50aWNhdGVkKVxuICAgICAgICAgICAgICAgIC5vbigndW5hdXRob3JpemVkJywgb25VbmF1dGhvcml6ZWQpXG4gICAgICAgICAgICAgICAgLm9uKCdsb2dnZWRfb3V0Jywgb25Mb2dPdXQpXG4gICAgICAgICAgICAgICAgLm9uKCdkaXNjb25uZWN0Jywgb25EaXNjb25uZWN0KTtcblxuICAgICAgICAgICAgLy8gVE9ETzogdGhpcyBmb2xsb3dvd2luZyBldmVudCBpcyBzdGlsbCB1c2VkLj8/Py4uLi5cbiAgICAgICAgICAgIHNvY2tldFxuICAgICAgICAgICAgICAgIC5vbignY29ubmVjdF9lcnJvcicsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuICAgICAgICAgICAgZnVuY3Rpb24gb25Db25uZWN0KCkge1xuICAgICAgICAgICAgICAgIC8vIHRoZSBzb2NrZXQgaXMgY29ubmVjdGVkLCB0aW1lIHRvIHBhc3MgdGhlIHRva2VuIHRvIGF1dGhlbnRpY2F0ZSBhc2FwXG4gICAgICAgICAgICAgICAgLy8gYmVjYXVzZSB0aGUgdG9rZW4gaXMgYWJvdXQgdG8gZXhwaXJlLi4uaWYgaXQgZXhwaXJlcyB3ZSB3aWxsIGhhdmUgdG8gcmVsb2cgaW5cbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICBzb2NrZXQuZW1pdCgnYXV0aGVudGljYXRlJywgeyB0b2tlbjogdXNlclRva2VuIH0pOyAvLyBzZW5kIHRoZSBqd3RcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gb25EaXNjb25uZWN0KCkge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ1Nlc3Npb24gZGlzY29ubmVjdGVkJyk7XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uQXV0aGVudGljYXRlZChyZWZyZXNoVG9rZW4pIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIC8vIHRoZSBzZXJ2ZXIgY29uZmlybWVkIHRoYXQgdGhlIHRva2VuIGlzIHZhbGlkLi4ud2UgYXJlIGdvb2QgdG8gZ29cbiAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdhdXRoZW50aWNhdGVkLCByZWNlaXZlZCBuZXcgdG9rZW46ICcgKyAocmVmcmVzaFRva2VuICE9IHVzZXJUb2tlbikpO1xuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS50b2tlbiA9IHJlZnJlc2hUb2tlbjtcbiAgICAgICAgICAgICAgICB1c2VyVG9rZW4gPSByZWZyZXNoVG9rZW47XG4gICAgICAgICAgICAgICAgc2V0TG9naW5Vc2VyKHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyh0cnVlKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0TmV3VG9rZW5CZWZvcmVFeHBpcmF0aW9uKHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KCd1c2VyX2Nvbm5lY3RlZCcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkxvZ091dCgpIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIC8vIHRva2VuIGlzIG5vIGxvbmdlciBhdmFpbGFibGUuXG4gICAgICAgICAgICAgICAgZGVsZXRlIGxvY2FsU3RvcmFnZS50b2tlbjtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICByZWRpcmVjdChsb2dvdXRVcmwgfHwgbG9naW5VcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvblVuYXV0aG9yaXplZChtc2cpIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ3VuYXV0aG9yaXplZDogJyArIEpTT04uc3RyaW5naWZ5KG1zZy5kYXRhKSk7XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgcmVkaXJlY3QobG9naW5VcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBzZXRDb25uZWN0aW9uU3RhdHVzKGNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmNvbm5lY3RlZCA9IGNvbm5lY3RlZDtcbiAgICAgICAgICAgICAgICAvL2NvbnNvbGUuZGVidWcoXCJDb25uZWN0aW9uIHN0YXR1czpcIiArIEpTT04uc3RyaW5naWZ5KHNlc3Npb25Vc2VyKSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHNldExvZ2luVXNlcih0b2tlbikge1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gZGVjb2RlKHRva2VuKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5pZCA9IHBheWxvYWQuaWQ7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIuZGlzcGxheSA9IHBheWxvYWQuZGlzcGxheTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5maXJzdE5hbWUgPSBwYXlsb2FkLmZpcnN0TmFtZTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5sYXN0TmFtZSA9IHBheWxvYWQubGFzdE5hbWU7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIucm9sZSA9IHBheWxvYWQucm9sZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gY2xlYXJUb2tlblRpbWVvdXQoKSB7XG4gICAgICAgICAgICAgICAgaWYgKHRva2VuVmFsaWRpdHlUaW1lb3V0KSB7XG4gICAgICAgICAgICAgICAgICAgICR0aW1lb3V0LmNhbmNlbCh0b2tlblZhbGlkaXR5VGltZW91dCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBkZWNvZGUodG9rZW4pIHtcbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0VXJsID0gdG9rZW4uc3BsaXQoJy4nKVsxXTtcbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0ID0gYmFzZTY0VXJsLnJlcGxhY2UoJy0nLCAnKycpLnJlcGxhY2UoJ18nLCAnLycpO1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gSlNPTi5wYXJzZSgkd2luZG93LmF0b2IoYmFzZTY0KSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHBheWxvYWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHJlcXVlc3ROZXdUb2tlbkJlZm9yZUV4cGlyYXRpb24odG9rZW4pIHtcbiAgICAgICAgICAgICAgICAvLyByZXF1ZXN0IGEgbGl0dGxlIGJlZm9yZS4uLlxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gZGVjb2RlKHRva2VuLCB7IGNvbXBsZXRlOiBmYWxzZSB9KTtcblxuICAgICAgICAgICAgICAgIHZhciBpbml0aWFsID0gcGF5bG9hZC5kdXI7XG5cbiAgICAgICAgICAgICAgICB2YXIgZHVyYXRpb24gPSAoaW5pdGlhbCAqIDkwIC8gMTAwKSB8IDA7XG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnU2NoZWR1bGUgdG8gcmVxdWVzdCBhIG5ldyB0b2tlbiBpbiAnICsgZHVyYXRpb24gKyAnIHNlY29uZHMgKHRva2VuIGR1cmF0aW9uOicgKyBpbml0aWFsICsgJyknKTtcbiAgICAgICAgICAgICAgICB0b2tlblZhbGlkaXR5VGltZW91dCA9ICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnVGltZSB0byByZXF1ZXN0IG5ldyB0b2tlbiAnICsgaW5pdGlhbCk7XG4gICAgICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KCdhdXRoZW50aWNhdGUnLCB7IHRva2VuOiB0b2tlbiB9KTtcbiAgICAgICAgICAgICAgICAgICAgLy8gTm90ZTogSWYgY29tbXVuaWNhdGlvbiBjcmFzaGVzIHJpZ2h0IGFmdGVyIHdlIGVtaXR0ZWQgYW5kIHdoZW4gc2VydmVycyBpcyBzZW5kaW5nIGJhY2sgdGhlIHRva2VuLFxuICAgICAgICAgICAgICAgICAgICAvLyB3aGVuIHRoZSBjbGllbnQgcmVlc3RhYmxpc2hlcyB0aGUgY29ubmVjdGlvbiwgd2Ugd291bGQgaGF2ZSB0byBsb2dpbiBiZWNhdXNlIHRoZSBwcmV2aW91cyB0b2tlbiB3b3VsZCBiZSBpbnZhbGlkYXRlZC5cbiAgICAgICAgICAgICAgICB9LCBkdXJhdGlvbiAqIDEwMDApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gcmV0cmlldmVUb2tlbigpIHtcbiAgICAgICAgICAgIHZhciB1c2VyVG9rZW4gPSAkbG9jYXRpb24uc2VhcmNoKCkudG9rZW47XG4gICAgICAgICAgICBpZiAodXNlclRva2VuKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnVXNpbmcgdG9rZW4gcGFzc2VkIGR1cmluZyByZWRpcmVjdGlvbjogJyArIHVzZXJUb2tlbik7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHVzZXJUb2tlbiA9IGxvY2FsU3RvcmFnZS50b2tlbjtcbiAgICAgICAgICAgICAgICBpZiAodXNlclRva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ1VzaW5nIFRva2VuIGluIGxvY2FsIHN0b3JhZ2U6ICcgKyB1c2VyVG9rZW4pO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdXNlclRva2VuO1xuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gcmVkaXJlY3QodXJsKSB7XG4gICAgICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVwbGFjZSh1cmwgfHwgJ2JhZFVybC5odG1sJyk7XG4gICAgICAgIH1cbiAgICB9O1xufVxufSgpKTtcblxuKGZ1bmN0aW9uKCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbi8qKiBcbiAqIFRoaXMgc2VydmljZSBhbGxvd3MgeW91ciBhcHBsaWNhdGlvbiBjb250YWN0IHRoZSB3ZWJzb2NrZXQgYXBpLlxuICogXG4gKiBJdCB3aWxsIGVuc3VyZSB0aGF0IHRoZSBjb25uZWN0aW9uIGlzIGF2YWlsYWJsZSBhbmQgdXNlciBpcyBhdXRoZW50aWNhdGVkIGJlZm9yZSBmZXRjaGluZyBkYXRhLlxuICogXG4gKi9cbmFuZ3VsYXJcbiAgICAubW9kdWxlKCdzb2NrZXRpby1hdXRoJylcbiAgICAuc2VydmljZSgnJHNvY2tldGlvJywgc29ja2V0aW9TZXJ2aWNlKTtcblxuZnVuY3Rpb24gc29ja2V0aW9TZXJ2aWNlKCRyb290U2NvcGUsICRxLCAkYXV0aCkge1xuXG4gICAgdGhpcy5vbiA9IG9uO1xuICAgIHRoaXMuZW1pdCA9IGVtaXQ7XG4gICAgdGhpcy5sb2dvdXQgPSAkYXV0aC5sb2dvdXQ7XG4gICAgdGhpcy5mZXRjaCA9IGZldGNoO1xuICAgIHRoaXMucG9zdCA9IHBvc3Q7XG4gICAgdGhpcy5ub3RpZnkgPSBub3RpZnk7XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgZnVuY3Rpb24gb24oZXZlbnROYW1lLCBjYWxsYmFjaykge1xuICAgICAgICAkYXV0aC5jb25uZWN0KCkudGhlbihmdW5jdGlvbiAoc29ja2V0KSB7XG4gICAgICAgICAgICBzb2NrZXQub24oZXZlbnROYW1lLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYXBwbHkoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjay5hcHBseShzb2NrZXQsIGFyZ3MpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICAvLyBkZXByZWNhdGVkLCB1c2UgcG9zdC9ub3RpZnlcbiAgICBmdW5jdGlvbiBlbWl0KGV2ZW50TmFtZSwgZGF0YSwgY2FsbGJhY2spIHtcbiAgICAgICAgJGF1dGguY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKHNvY2tldCkge1xuICAgICAgICAgICAgc29ja2V0LmVtaXQoZXZlbnROYW1lLCBkYXRhLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYXBwbHkoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoY2FsbGJhY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrLmFwcGx5KHNvY2tldCwgYXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBmZXRjaCBkYXRhIHRoZSB3YXkgd2UgY2FsbCBhbiBhcGkgXG4gICAgICogaHR0cDovL3N0YWNrb3ZlcmZsb3cuY29tL3F1ZXN0aW9ucy8yMDY4NTIwOC93ZWJzb2NrZXQtdHJhbnNwb3J0LXJlbGlhYmlsaXR5LXNvY2tldC1pby1kYXRhLWxvc3MtZHVyaW5nLXJlY29ubmVjdGlvblxuICAgICAqIFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGZldGNoKG9wZXJhdGlvbiwgZGF0YSkge1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdGZXRjaGluZyAnICsgb3BlcmF0aW9uICsgJy4uLicpO1xuICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogbm90aWZ5IGlzIHNpbWlsYXIgdG8gZmV0Y2ggYnV0IG1vcmUgbWVhbmluZ2Z1bFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vdGlmeShvcGVyYXRpb24sIGRhdGEpIHtcbiAgICAgICAgY29uc29sZS5kZWJ1ZygnTm90aWZ5aW5nICcgKyBvcGVyYXRpb24gKyAnLi4uJyk7XG4gICAgICAgIHJldHVybiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSlcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBwb3N0IHNlbmRzIGRhdGEgdG8gdGhlIHNlcnZlci5cbiAgICAgKiBpZiBkYXRhIHdhcyBhbHJlYWR5IHN1Ym1pdHRlZCwgaXQgd291bGQganVzdCByZXR1cm4gLSB3aGljaCBjb3VsZCBoYXBwZW4gd2hlbiBoYW5kbGluZyBkaXNjb25uZWN0aW9uLlxuICAgICAqIFxuICAgICAqIE5vdGU6XG4gICAgICogIHRoZSBjb2RlIGFsc28gaGFuZGxlcyB2ZXJzaW9uaW5nIG9uIGFueSBwb3N0ZWQgZGF0YVxuICAgICAgICBBbGkgYW5kIEVtbWFudWVsIGRlY2lkZWQgbm90IHRvIHVzZSB0aGlzIHNvbHV0aW9uIGZvciBub3cuIGJ1dCBJKGVtbWFudWVsKSBhbSBub3QgcmVtb3ZpbmcgdGhlIGNvZGUgeWV0LiBJdCBkb2VzIGFkZCBhIHZlcnNpb24gdG8gYW4gb2JqZWN0LlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHBvc3Qob3BlcmF0aW9uLCBkYXRhKSB7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ1Bvc3RpbmcgJyArIG9wZXJhdGlvbiArICcuLi4nKTtcblxuXG4gICAgICAgIC8vIHdlIGRvIG5vdCBtYW5hZ2UgdmVyc2lvbmluZyBvbiBzdHJpbmcsIG51bWJlciwgZGF0ZSAoVE9ETyB1c2UgbG9kYXNoKVxuICAgICAgICBpZiAodHlwZW9mIGRhdGEgPT09ICdzdHJpbmcnIHx8IGRhdGEgaW5zdGFuY2VvZiBTdHJpbmcgfHwgIGRhdGEgaW5zdGFuY2VvZiBEYXRlIHx8IHR5cGVvZiBkYXRhID09PSAnbnVtYmVyJyB8fCB0eXBlb2YgZGF0YSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFkYXRhLnZlcnNpb24pIHtcbiAgICAgICAgICAgIGRhdGEudmVyc2lvbiA9IC0xO1xuICAgICAgICB9IGVsc2UgaWYgKGRhdGEudmVyc2lvbiA+IDApIHtcbiAgICAgICAgICAgIC8vIGlmIHBvc2l0aXZlIG1lYW5zIHdlIGhhdmUgbm90IGluY3JlYXNlIHRoZSB2ZXJzaW9uIHlldFxuICAgICAgICAgICAgZGF0YS52ZXJzaW9uID0gLWRhdGEudmVyc2lvbiAtIDE7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHNvY2tldEVtaXQob3BlcmF0aW9uLCBkYXRhKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgLy8gaWYgc3VjY2VzcywgdmVyc2lvbiBpcyBiYWNrIHRvIHBvc2l0aXZlXG4gICAgICAgICAgICAgICAgZGF0YS52ZXJzaW9uID0gTWF0aC5hYnMoZGF0YS52ZXJzaW9uKTtcbiAgICAgICAgICAgICAgICAvLyB0aGUgcmVzcG9uc2Ugc2hvdWxkIGhhdmUgdGhlIHZlcnNpb24gdG9vLi4uXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICAgICAgICAgLy8gaWYgYmFja2VuZCBoYXMgYWxyZWFkeSByZWNlaXZlZCB0aGlzIHZlcnNpb24gZnJvbSB0aGlzIHVzZXIgKHRva2VuKS4uLlxuICAgICAgICAgICAgICAgIGlmIChlcnIuY29kZSA9PSAnQUxSRUFEWV9TVUJNSVRURUQnKSB7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudmVyc2lvbiA9IE1hdGguYWJzKGRhdGEudmVyc2lvbik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZXNvbHZlKGRhdGEpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpIHtcblxuICAgICAgICByZXR1cm4gJGF1dGguY29ubmVjdCgpXG4gICAgICAgICAgICAudGhlbihvbkNvbm5lY3Rpb25TdWNjZXNzLCBvbkNvbm5lY3Rpb25FcnJvcilcbiAgICAgICAgICAgIDsvLyAuY2F0Y2gob25Db25uZWN0aW9uRXJyb3IpO1xuXG4gICAgICAgIC8vLy8vLy8vLy8vL1xuICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3Rpb25TdWNjZXNzKHNvY2tldCkge1xuICAgICAgICAgICAgLy8gYnV0IHdoYXQgaWYgd2UgaGF2ZSBub3QgY29ubmVjdGlvbiBiZWZvcmUgdGhlIGVtaXQsIGl0IHdpbGwgcXVldWUgY2FsbC4uLm5vdCBzbyBnb29kLiAgICAgICAgXG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2FwaScsIG9wZXJhdGlvbiwgZGF0YSwgZnVuY3Rpb24gKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgIGlmIChyZXN1bHQuY29kZSkge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdFcnJvciBvbiAnICsgb3BlcmF0aW9uICsgJyAtPicgKyBKU09OLnN0cmluZ2lmeShyZXN1bHQpKTtcbiAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KHsgY29kZTogcmVzdWx0LmNvZGUsIGRlc2NyaXB0aW9uOiByZXN1bHQuZGF0YSB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzdWx0LmRhdGEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3Rpb25FcnJvcihlcnIpIHtcbiAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBjb2RlOiAnQ09OTkVDVElPTl9FUlInLCBkZXNjcmlwdGlvbjogZXJyIH0pO1xuICAgICAgICB9XG4gICAgfVxufVxufSgpKTtcblxuIiwiYW5ndWxhci5tb2R1bGUoJ3NvY2tldGlvLWF1dGgnLCBbXSk7XG4iLCJcbi8qKiBcbiAqIFRoaXMgcHJvdmlkZXIgaGFuZGxlcyB0aGUgaGFuZHNoYWtlIHRvIGF1dGhlbnRpY2F0ZSBhIHVzZXIgYW5kIG1haW50YWluIGEgc2VjdXJlIHdlYiBzb2NrZXQgY29ubmVjdGlvbiB2aWEgdG9rZW5zLlxuICogSXQgYWxzbyBzZXRzIHRoZSBsb2dpbiBhbmQgbG9nb3V0IHVybCBwYXJ0aWNpcGF0aW5nIGluIHRoZSBhdXRoZW50aWNhdGlvbi5cbiAqIFxuICogXG4gKiB1c2FnZSBleGFtcGxlczpcbiAqIFxuICogSW4gdGhlIGNvbmZpZyBvZiB0aGUgYXBwIG1vZHVsZTpcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRMb2dpblVybCgnL2FjY2VzcyMvbG9naW4nKTtcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRMb2dvdXRVcmwoJy9hY2Nlc3MjL2xvZ2luJyk7XG4gKiBzb2NrZXRTZXJ2aWNlUHJvdmlkZXIuc2V0UmVjb25uZWN0aW9uTWF4VGltZUluU2VjcygxNSk7XG4gKiBUaGlzIGRlZmluZXMgaG93IG11Y2ggdGltZSB3ZSBjYW4gd2FpdCB0byBlc3RhYmxpc2ggYSBzdWNjZXNzdWwgY29ubmVjdGlvbiBiZWZvcmUgcmVqZWN0aW5nIHRoZSBjb25uZWN0aW9uIChzb2NrZXRTZXJ2aWNlLmNvbm5lY3RJTykgd2l0aCBhIHRpbWVvdXQuIGJ5IGRlZmF1bHQsIGl0IHdpbGwgdHJ5IGZvciAxNSBzZWNvbmRzIHRvIGdldCBhIGNvbm5lY3Rpb24gYW5kIHRoZW4gZ2l2ZSB1cFxuICogIFxuICogQmVmb3JlIGFueSBzb2NrZXQgdXNlIGluIHlvdXIgc2VydmljZXMgb3IgcmVzb2x2ZSBibG9ja3MsIGNvbm5lY3QoKSBtYWtlcyBzdXJlIHRoYXQgd2UgaGF2ZSBhbiBlc3RhYmxpc2hlZCBhdXRoZW50aWNhdGVkIGNvbm5lY3Rpb24gYnkgdXNpbmcgdGhlIGZvbGxvd2luZzpcbiAqIHNvY2tldFNlcnZpY2UuY29ubmVjdCgpLnRoZW4oXG4gKiBmdW5jdGlvbihzb2NrZXQpeyAuLi4gc29ja2V0LmVtaXQoKS4uIH0pLmNhdGNoKGZ1bmN0aW9uKGVycikgey4uLn0pXG4gKiBcbiAqIFxuICovXG5hbmd1bGFyXG4gICAgLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcpXG4gICAgLnByb3ZpZGVyKCckYXV0aCcsIGF1dGhQcm92aWRlcik7XG5cbmZ1bmN0aW9uIGF1dGhQcm92aWRlcigpIHtcblxuICAgIHZhciBsb2dpblVybCwgbG9nb3V0VXJsLCByZWNvbm5lY3Rpb25NYXhUaW1lID0gMTU7XG5cbiAgICB0aGlzLnNldExvZ2luVXJsID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgIGxvZ2luVXJsID0gdmFsdWU7XG4gICAgfTtcblxuICAgIHRoaXMuc2V0TG9nb3V0VXJsID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgIGxvZ291dFVybCA9IHZhbHVlO1xuICAgIH07XG5cbiAgICB0aGlzLnNldFJlY29ubmVjdGlvbk1heFRpbWVJblNlY3MgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgcmVjb25uZWN0aW9uTWF4VGltZSA9IHZhbHVlICogMTAwMDtcbiAgICB9O1xuXG4gICAgdGhpcy4kZ2V0ID0gZnVuY3Rpb24gKCRyb290U2NvcGUsICRsb2NhdGlvbiwgJHRpbWVvdXQsICRxLCAkd2luZG93KSB7XG5cbiAgICAgICAgdmFyIHNvY2tldDtcbiAgICAgICAgdmFyIHVzZXJUb2tlbiA9IHJldHJpZXZlVG9rZW4oKTtcbiAgICAgICAgdmFyIHNlc3Npb25Vc2VyID0ge307XG4gICAgICAgICRyb290U2NvcGUuc2Vzc2lvblVzZXIgPSBzZXNzaW9uVXNlcjtcblxuICAgICAgICBpZiAoIXVzZXJUb2tlbikge1xuICAgICAgICAgICAgLy8gQFRPRE86IHRoaXMgcmlnaHQgd2F5IHRvIHJlZGlyZWN0IGlmIHdlIGhhdmUgbm8gdG9rZW4gd2hlbiB3ZSByZWZyZXNoIG9yIGhpdCB0aGUgYXBwLlxuICAgICAgICAgICAgLy8gIHJlZGlyZWN0KGxvZ2luVXJsKTtcbiAgICAgICAgICAgIC8vIGJ1dCBpdCB3b3VsZCBwcmV2ZW50IG1vc3QgdW5pdCB0ZXN0cyBmcm9tIHJ1bm5pbmcgYmVjYXVzZSB0aGlzIG1vZHVsZSBpcyB0aWdobHkgY291cGxlZCB3aXRoIGFsbCB1bml0IHRlc3RzIChkZXBlbmRzIG9uIGl0KWF0IHRoaXMgdGltZSA6XG5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGxvY2FsU3RvcmFnZS50b2tlbiA9IHVzZXJUb2tlbjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgY29ubmVjdDogY29ubmVjdCxcbiAgICAgICAgICAgIGxvZ291dDogbG9nb3V0XG4gICAgICAgIH07XG5cbiAgICAgICAgLy8vLy8vLy8vLy8vLy8vLy8vL1xuICAgICAgICAvKipcbiAgICAgICAgICogcmV0dXJucyBhIHByb21pc2UgXG4gICAgICAgICAqIHRoZSBzdWNjZXNzIGZ1bmN0aW9uIHJlY2VpdmVzIHRoZSBzb2NrZXQgYXMgYSBwYXJhbWV0ZXJcbiAgICAgICAgICovXG4gICAgICAgIGZ1bmN0aW9uIGNvbm5lY3QoKSB7XG4gICAgICAgICAgICBpZiAoIXNvY2tldCkge1xuICAgICAgICAgICAgICAgIHNldHVwKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZ2V0Rm9yVmFsaWRDb25uZWN0aW9uKCk7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICAgICAgICAvLyBjb25uZWN0aW9uIGNvdWxkIGJlIGxvc3QgZHVyaW5nIGxvZ291dC4uc28gaXQgY291bGQgbWVhbiB3ZSBoYXZlIG5vdCBsb2dvdXQgb24gc2VydmVyIHNpZGUuXG4gICAgICAgICAgICBpZiAoc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2xvZ291dCcsIHVzZXJUb2tlbik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBnZXRGb3JWYWxpZENvbm5lY3Rpb24oKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuICAgICAgICAgICAgaWYgKHNlc3Npb25Vc2VyLmNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgLy8gYmVpbmcgdGhlIHNjZW5lLCBzb2NrZXQuaW8gaXMgdHJ5aW5nIHRvIHJlY29ubmVjdCBhbmQgYXV0aGVudGljYXRlIGlmIHRoZSBjb25uZWN0aW9uIHdhcyBsb3N0O1xuICAgICAgICAgICAgICAgIHJlY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHNvY2tldCk7XG4gICAgICAgICAgICAgICAgfSkuY2F0Y2goZnVuY3Rpb24gKGVycikge1xuICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoJ1VTRVJfTk9UX0NPTk5FQ1RFRCcpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZWNvbm5lY3QoKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgICBpZiAoc2Vzc2lvblVzZXIuY29ubmVjdGVkKSB7XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy9AVE9ETyBUTyBUSElOSyBBQk9VVDosIGlmIHRoZSBzb2NrZXQgaXMgY29ubmVjdGluZyBhbHJlYWR5LCBtZWFucyB0aGF0IGEgY29ubmVjdCB3YXMgY2FsbGVkIGFscmVhZHkgYnkgYW5vdGhlciBhc3luYyBjYWxsLCBzbyBqdXN0IHdhaXQgZm9yIHVzZXJfY29ubmVjdGVkXG4gICAgICAgICAgICBcbiAgICAgICAgICAgIFxuICAgICAgICAgICAgXG4gICAgICAgICAgICAvLyBpZiB0aGUgcmVzcG9uc2UgZG9lcyBub3QgY29tZSBxdWljay4ubGV0J3MgZ2l2ZSB1cCBzbyB3ZSBkb24ndCBnZXQgc3R1Y2sgd2FpdGluZ1xuICAgICAgICAgICAgLy8gQFRPRE86b3RoZXIgd2F5IGlzIHRvIHdhdGNoIGZvciBhIGNvbm5lY3Rpb24gZXJyb3IuLi5cbiAgICAgICAgICAgIHZhciBhY2NlcHRhYmxlRGVsYXk7XG4gICAgICAgICAgICB2YXIgb2ZmID0gJHJvb3RTY29wZS4kb24oJ3VzZXJfY29ubmVjdGVkJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIG9mZigpO1xuICAgICAgICAgICAgICAgIGlmIChhY2NlcHRhYmxlRGVsYXkpIHtcbiAgICAgICAgICAgICAgICAgICAgJHRpbWVvdXQuY2FuY2VsKGFjY2VwdGFibGVEZWxheSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICBhY2NlcHRhYmxlRGVsYXkgPSAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgb2ZmKCk7XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KCdUSU1FT1VUJyk7XG4gICAgICAgICAgICB9LCByZWNvbm5lY3Rpb25NYXhUaW1lKTtcblxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBzZXR1cCgpIHtcbiAgICAgICAgICAgIGlmIChzb2NrZXQpIHtcbiAgICAgICAgICAgICAgICAvL2FscmVhZHkgY2FsbGVkLi4uXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdmFyIHRva2VuVmFsaWRpdHlUaW1lb3V0O1xuICAgICAgICAgICAgLy8gZXN0YWJsaXNoIGNvbm5lY3Rpb24gd2l0aG91dCBwYXNzaW5nIHRoZSB0b2tlbiAoc28gdGhhdCBpdCBpcyBub3QgdmlzaWJsZSBpbiB0aGUgbG9nKVxuICAgICAgICAgICAgc29ja2V0ID0gaW8uY29ubmVjdCh7XG4gICAgICAgICAgICAgICAgJ2ZvcmNlTmV3JzogdHJ1ZSxcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICBzb2NrZXRcbiAgICAgICAgICAgICAgICAub24oJ2Nvbm5lY3QnLCBvbkNvbm5lY3QpXG4gICAgICAgICAgICAgICAgLm9uKCdhdXRoZW50aWNhdGVkJywgb25BdXRoZW50aWNhdGVkKVxuICAgICAgICAgICAgICAgIC5vbigndW5hdXRob3JpemVkJywgb25VbmF1dGhvcml6ZWQpXG4gICAgICAgICAgICAgICAgLm9uKCdsb2dnZWRfb3V0Jywgb25Mb2dPdXQpXG4gICAgICAgICAgICAgICAgLm9uKCdkaXNjb25uZWN0Jywgb25EaXNjb25uZWN0KTtcblxuICAgICAgICAgICAgLy8gVE9ETzogdGhpcyBmb2xsb3dvd2luZyBldmVudCBpcyBzdGlsbCB1c2VkLj8/Py4uLi5cbiAgICAgICAgICAgIHNvY2tldFxuICAgICAgICAgICAgICAgIC5vbignY29ubmVjdF9lcnJvcicsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuICAgICAgICAgICAgZnVuY3Rpb24gb25Db25uZWN0KCkge1xuICAgICAgICAgICAgICAgIC8vIHRoZSBzb2NrZXQgaXMgY29ubmVjdGVkLCB0aW1lIHRvIHBhc3MgdGhlIHRva2VuIHRvIGF1dGhlbnRpY2F0ZSBhc2FwXG4gICAgICAgICAgICAgICAgLy8gYmVjYXVzZSB0aGUgdG9rZW4gaXMgYWJvdXQgdG8gZXhwaXJlLi4uaWYgaXQgZXhwaXJlcyB3ZSB3aWxsIGhhdmUgdG8gcmVsb2cgaW5cbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICBzb2NrZXQuZW1pdCgnYXV0aGVudGljYXRlJywgeyB0b2tlbjogdXNlclRva2VuIH0pOyAvLyBzZW5kIHRoZSBqd3RcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gb25EaXNjb25uZWN0KCkge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ1Nlc3Npb24gZGlzY29ubmVjdGVkJyk7XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uQXV0aGVudGljYXRlZChyZWZyZXNoVG9rZW4pIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIC8vIHRoZSBzZXJ2ZXIgY29uZmlybWVkIHRoYXQgdGhlIHRva2VuIGlzIHZhbGlkLi4ud2UgYXJlIGdvb2QgdG8gZ29cbiAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdhdXRoZW50aWNhdGVkLCByZWNlaXZlZCBuZXcgdG9rZW46ICcgKyAocmVmcmVzaFRva2VuICE9IHVzZXJUb2tlbikpO1xuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS50b2tlbiA9IHJlZnJlc2hUb2tlbjtcbiAgICAgICAgICAgICAgICB1c2VyVG9rZW4gPSByZWZyZXNoVG9rZW47XG4gICAgICAgICAgICAgICAgc2V0TG9naW5Vc2VyKHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyh0cnVlKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0TmV3VG9rZW5CZWZvcmVFeHBpcmF0aW9uKHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KCd1c2VyX2Nvbm5lY3RlZCcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkxvZ091dCgpIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIC8vIHRva2VuIGlzIG5vIGxvbmdlciBhdmFpbGFibGUuXG4gICAgICAgICAgICAgICAgZGVsZXRlIGxvY2FsU3RvcmFnZS50b2tlbjtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICByZWRpcmVjdChsb2dvdXRVcmwgfHwgbG9naW5VcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvblVuYXV0aG9yaXplZChtc2cpIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ3VuYXV0aG9yaXplZDogJyArIEpTT04uc3RyaW5naWZ5KG1zZy5kYXRhKSk7XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgcmVkaXJlY3QobG9naW5VcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBzZXRDb25uZWN0aW9uU3RhdHVzKGNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmNvbm5lY3RlZCA9IGNvbm5lY3RlZDtcbiAgICAgICAgICAgICAgICAvL2NvbnNvbGUuZGVidWcoXCJDb25uZWN0aW9uIHN0YXR1czpcIiArIEpTT04uc3RyaW5naWZ5KHNlc3Npb25Vc2VyKSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHNldExvZ2luVXNlcih0b2tlbikge1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gZGVjb2RlKHRva2VuKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5pZCA9IHBheWxvYWQuaWQ7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIuZGlzcGxheSA9IHBheWxvYWQuZGlzcGxheTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5maXJzdE5hbWUgPSBwYXlsb2FkLmZpcnN0TmFtZTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5sYXN0TmFtZSA9IHBheWxvYWQubGFzdE5hbWU7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIucm9sZSA9IHBheWxvYWQucm9sZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gY2xlYXJUb2tlblRpbWVvdXQoKSB7XG4gICAgICAgICAgICAgICAgaWYgKHRva2VuVmFsaWRpdHlUaW1lb3V0KSB7XG4gICAgICAgICAgICAgICAgICAgICR0aW1lb3V0LmNhbmNlbCh0b2tlblZhbGlkaXR5VGltZW91dCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBkZWNvZGUodG9rZW4pIHtcbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0VXJsID0gdG9rZW4uc3BsaXQoJy4nKVsxXTtcbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0ID0gYmFzZTY0VXJsLnJlcGxhY2UoJy0nLCAnKycpLnJlcGxhY2UoJ18nLCAnLycpO1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gSlNPTi5wYXJzZSgkd2luZG93LmF0b2IoYmFzZTY0KSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHBheWxvYWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHJlcXVlc3ROZXdUb2tlbkJlZm9yZUV4cGlyYXRpb24odG9rZW4pIHtcbiAgICAgICAgICAgICAgICAvLyByZXF1ZXN0IGEgbGl0dGxlIGJlZm9yZS4uLlxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gZGVjb2RlKHRva2VuLCB7IGNvbXBsZXRlOiBmYWxzZSB9KTtcblxuICAgICAgICAgICAgICAgIHZhciBpbml0aWFsID0gcGF5bG9hZC5kdXI7XG5cbiAgICAgICAgICAgICAgICB2YXIgZHVyYXRpb24gPSAoaW5pdGlhbCAqIDkwIC8gMTAwKSB8IDA7XG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnU2NoZWR1bGUgdG8gcmVxdWVzdCBhIG5ldyB0b2tlbiBpbiAnICsgZHVyYXRpb24gKyAnIHNlY29uZHMgKHRva2VuIGR1cmF0aW9uOicgKyBpbml0aWFsICsgJyknKTtcbiAgICAgICAgICAgICAgICB0b2tlblZhbGlkaXR5VGltZW91dCA9ICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnVGltZSB0byByZXF1ZXN0IG5ldyB0b2tlbiAnICsgaW5pdGlhbCk7XG4gICAgICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KCdhdXRoZW50aWNhdGUnLCB7IHRva2VuOiB0b2tlbiB9KTtcbiAgICAgICAgICAgICAgICAgICAgLy8gTm90ZTogSWYgY29tbXVuaWNhdGlvbiBjcmFzaGVzIHJpZ2h0IGFmdGVyIHdlIGVtaXR0ZWQgYW5kIHdoZW4gc2VydmVycyBpcyBzZW5kaW5nIGJhY2sgdGhlIHRva2VuLFxuICAgICAgICAgICAgICAgICAgICAvLyB3aGVuIHRoZSBjbGllbnQgcmVlc3RhYmxpc2hlcyB0aGUgY29ubmVjdGlvbiwgd2Ugd291bGQgaGF2ZSB0byBsb2dpbiBiZWNhdXNlIHRoZSBwcmV2aW91cyB0b2tlbiB3b3VsZCBiZSBpbnZhbGlkYXRlZC5cbiAgICAgICAgICAgICAgICB9LCBkdXJhdGlvbiAqIDEwMDApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gcmV0cmlldmVUb2tlbigpIHtcbiAgICAgICAgICAgIHZhciB1c2VyVG9rZW4gPSAkbG9jYXRpb24uc2VhcmNoKCkudG9rZW47XG4gICAgICAgICAgICBpZiAodXNlclRva2VuKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnVXNpbmcgdG9rZW4gcGFzc2VkIGR1cmluZyByZWRpcmVjdGlvbjogJyArIHVzZXJUb2tlbik7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHVzZXJUb2tlbiA9IGxvY2FsU3RvcmFnZS50b2tlbjtcbiAgICAgICAgICAgICAgICBpZiAodXNlclRva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ1VzaW5nIFRva2VuIGluIGxvY2FsIHN0b3JhZ2U6ICcgKyB1c2VyVG9rZW4pO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdXNlclRva2VuO1xuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gcmVkaXJlY3QodXJsKSB7XG4gICAgICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVwbGFjZSh1cmwgfHwgJ2JhZFVybC5odG1sJyk7XG4gICAgICAgIH1cbiAgICB9O1xufVxuXG4iLCJcbi8qKiBcbiAqIFRoaXMgc2VydmljZSBhbGxvd3MgeW91ciBhcHBsaWNhdGlvbiBjb250YWN0IHRoZSB3ZWJzb2NrZXQgYXBpLlxuICogXG4gKiBJdCB3aWxsIGVuc3VyZSB0aGF0IHRoZSBjb25uZWN0aW9uIGlzIGF2YWlsYWJsZSBhbmQgdXNlciBpcyBhdXRoZW50aWNhdGVkIGJlZm9yZSBmZXRjaGluZyBkYXRhLlxuICogXG4gKi9cbmFuZ3VsYXJcbiAgICAubW9kdWxlKCdzb2NrZXRpby1hdXRoJylcbiAgICAuc2VydmljZSgnJHNvY2tldGlvJywgc29ja2V0aW9TZXJ2aWNlKTtcblxuZnVuY3Rpb24gc29ja2V0aW9TZXJ2aWNlKCRyb290U2NvcGUsICRxLCAkYXV0aCkge1xuXG4gICAgdGhpcy5vbiA9IG9uO1xuICAgIHRoaXMuZW1pdCA9IGVtaXQ7XG4gICAgdGhpcy5sb2dvdXQgPSAkYXV0aC5sb2dvdXQ7XG4gICAgdGhpcy5mZXRjaCA9IGZldGNoO1xuICAgIHRoaXMucG9zdCA9IHBvc3Q7XG4gICAgdGhpcy5ub3RpZnkgPSBub3RpZnk7XG5cbiAgICAvLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgZnVuY3Rpb24gb24oZXZlbnROYW1lLCBjYWxsYmFjaykge1xuICAgICAgICAkYXV0aC5jb25uZWN0KCkudGhlbihmdW5jdGlvbiAoc29ja2V0KSB7XG4gICAgICAgICAgICBzb2NrZXQub24oZXZlbnROYW1lLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYXBwbHkoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjay5hcHBseShzb2NrZXQsIGFyZ3MpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICAvLyBkZXByZWNhdGVkLCB1c2UgcG9zdC9ub3RpZnlcbiAgICBmdW5jdGlvbiBlbWl0KGV2ZW50TmFtZSwgZGF0YSwgY2FsbGJhY2spIHtcbiAgICAgICAgJGF1dGguY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKHNvY2tldCkge1xuICAgICAgICAgICAgc29ja2V0LmVtaXQoZXZlbnROYW1lLCBkYXRhLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYXBwbHkoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoY2FsbGJhY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrLmFwcGx5KHNvY2tldCwgYXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBmZXRjaCBkYXRhIHRoZSB3YXkgd2UgY2FsbCBhbiBhcGkgXG4gICAgICogaHR0cDovL3N0YWNrb3ZlcmZsb3cuY29tL3F1ZXN0aW9ucy8yMDY4NTIwOC93ZWJzb2NrZXQtdHJhbnNwb3J0LXJlbGlhYmlsaXR5LXNvY2tldC1pby1kYXRhLWxvc3MtZHVyaW5nLXJlY29ubmVjdGlvblxuICAgICAqIFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIGZldGNoKG9wZXJhdGlvbiwgZGF0YSkge1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdGZXRjaGluZyAnICsgb3BlcmF0aW9uICsgJy4uLicpO1xuICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogbm90aWZ5IGlzIHNpbWlsYXIgdG8gZmV0Y2ggYnV0IG1vcmUgbWVhbmluZ2Z1bFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIG5vdGlmeShvcGVyYXRpb24sIGRhdGEpIHtcbiAgICAgICAgY29uc29sZS5kZWJ1ZygnTm90aWZ5aW5nICcgKyBvcGVyYXRpb24gKyAnLi4uJyk7XG4gICAgICAgIHJldHVybiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSlcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBwb3N0IHNlbmRzIGRhdGEgdG8gdGhlIHNlcnZlci5cbiAgICAgKiBpZiBkYXRhIHdhcyBhbHJlYWR5IHN1Ym1pdHRlZCwgaXQgd291bGQganVzdCByZXR1cm4gLSB3aGljaCBjb3VsZCBoYXBwZW4gd2hlbiBoYW5kbGluZyBkaXNjb25uZWN0aW9uLlxuICAgICAqIFxuICAgICAqIE5vdGU6XG4gICAgICogIHRoZSBjb2RlIGFsc28gaGFuZGxlcyB2ZXJzaW9uaW5nIG9uIGFueSBwb3N0ZWQgZGF0YVxuICAgICAgICBBbGkgYW5kIEVtbWFudWVsIGRlY2lkZWQgbm90IHRvIHVzZSB0aGlzIHNvbHV0aW9uIGZvciBub3cuIGJ1dCBJKGVtbWFudWVsKSBhbSBub3QgcmVtb3ZpbmcgdGhlIGNvZGUgeWV0LiBJdCBkb2VzIGFkZCBhIHZlcnNpb24gdG8gYW4gb2JqZWN0LlxuICAgICAqL1xuICAgIGZ1bmN0aW9uIHBvc3Qob3BlcmF0aW9uLCBkYXRhKSB7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ1Bvc3RpbmcgJyArIG9wZXJhdGlvbiArICcuLi4nKTtcblxuXG4gICAgICAgIC8vIHdlIGRvIG5vdCBtYW5hZ2UgdmVyc2lvbmluZyBvbiBzdHJpbmcsIG51bWJlciwgZGF0ZSAoVE9ETyB1c2UgbG9kYXNoKVxuICAgICAgICBpZiAodHlwZW9mIGRhdGEgPT09ICdzdHJpbmcnIHx8IGRhdGEgaW5zdGFuY2VvZiBTdHJpbmcgfHwgIGRhdGEgaW5zdGFuY2VvZiBEYXRlIHx8IHR5cGVvZiBkYXRhID09PSAnbnVtYmVyJyB8fCB0eXBlb2YgZGF0YSA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFkYXRhLnZlcnNpb24pIHtcbiAgICAgICAgICAgIGRhdGEudmVyc2lvbiA9IC0xO1xuICAgICAgICB9IGVsc2UgaWYgKGRhdGEudmVyc2lvbiA+IDApIHtcbiAgICAgICAgICAgIC8vIGlmIHBvc2l0aXZlIG1lYW5zIHdlIGhhdmUgbm90IGluY3JlYXNlIHRoZSB2ZXJzaW9uIHlldFxuICAgICAgICAgICAgZGF0YS52ZXJzaW9uID0gLWRhdGEudmVyc2lvbiAtIDE7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHNvY2tldEVtaXQob3BlcmF0aW9uLCBkYXRhKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgLy8gaWYgc3VjY2VzcywgdmVyc2lvbiBpcyBiYWNrIHRvIHBvc2l0aXZlXG4gICAgICAgICAgICAgICAgZGF0YS52ZXJzaW9uID0gTWF0aC5hYnMoZGF0YS52ZXJzaW9uKTtcbiAgICAgICAgICAgICAgICAvLyB0aGUgcmVzcG9uc2Ugc2hvdWxkIGhhdmUgdGhlIHZlcnNpb24gdG9vLi4uXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICAgICAgICAgLy8gaWYgYmFja2VuZCBoYXMgYWxyZWFkeSByZWNlaXZlZCB0aGlzIHZlcnNpb24gZnJvbSB0aGlzIHVzZXIgKHRva2VuKS4uLlxuICAgICAgICAgICAgICAgIGlmIChlcnIuY29kZSA9PSAnQUxSRUFEWV9TVUJNSVRURUQnKSB7XG4gICAgICAgICAgICAgICAgICAgIGRhdGEudmVyc2lvbiA9IE1hdGguYWJzKGRhdGEudmVyc2lvbik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZXNvbHZlKGRhdGEpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIH0pXG4gICAgfVxuXG4gICAgZnVuY3Rpb24gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpIHtcblxuICAgICAgICByZXR1cm4gJGF1dGguY29ubmVjdCgpXG4gICAgICAgICAgICAudGhlbihvbkNvbm5lY3Rpb25TdWNjZXNzLCBvbkNvbm5lY3Rpb25FcnJvcilcbiAgICAgICAgICAgIDsvLyAuY2F0Y2gob25Db25uZWN0aW9uRXJyb3IpO1xuXG4gICAgICAgIC8vLy8vLy8vLy8vL1xuICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3Rpb25TdWNjZXNzKHNvY2tldCkge1xuICAgICAgICAgICAgLy8gYnV0IHdoYXQgaWYgd2UgaGF2ZSBub3QgY29ubmVjdGlvbiBiZWZvcmUgdGhlIGVtaXQsIGl0IHdpbGwgcXVldWUgY2FsbC4uLm5vdCBzbyBnb29kLiAgICAgICAgXG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2FwaScsIG9wZXJhdGlvbiwgZGF0YSwgZnVuY3Rpb24gKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgIGlmIChyZXN1bHQuY29kZSkge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdFcnJvciBvbiAnICsgb3BlcmF0aW9uICsgJyAtPicgKyBKU09OLnN0cmluZ2lmeShyZXN1bHQpKTtcbiAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KHsgY29kZTogcmVzdWx0LmNvZGUsIGRlc2NyaXB0aW9uOiByZXN1bHQuZGF0YSB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzdWx0LmRhdGEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3Rpb25FcnJvcihlcnIpIHtcbiAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBjb2RlOiAnQ09OTkVDVElPTl9FUlInLCBkZXNjcmlwdGlvbjogZXJyIH0pO1xuICAgICAgICB9XG4gICAgfVxufVxuXG4iXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=
