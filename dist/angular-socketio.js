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
    // convenient service returning sessionUser
    .factory('sessionUser', ["$auth", function ($auth) {
        return $auth.getSessionUser();
    }])
    .provider('$auth', authProvider);

function authProvider() {

    var loginUrl, logoutUrl, debug, reconnectionMaxTime = 15;

    this.setDebug = function (value) {
        debug = value;
    };

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
        var sessionUser = { connected: false };

        if (!userToken) {
            // @TODO: this right way to redirect if we have no token when we refresh or hit the app.
            //  redirect(loginUrl);
            // but it would prevent most unit tests from running because this module is tighly coupled with all unit tests (depends on it)at this time :

        } else {
            localStorage.token = userToken;
        }
        return {
            connect: connect,
            logout: logout,
            getSessionUser: getSessionUser
        };


        ///////////////////

        function getSessionUser() {
            // the object will have the user information when the connection is established. Otherwise its connection property will be false; 
            return sessionUser;
        }

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
                if (debug) { console.debug('Session disconnected'); }
                setConnectionStatus(false);
                $rootScope.$broadcast('user_disconnected');
            }

            function onAuthenticated(refreshToken) {
                clearTokenTimeout();
                // the server confirmed that the token is valid...we are good to go
                if (debug) { console.debug('authenticated, received new token: ' + (refreshToken != userToken)); }
                localStorage.token = refreshToken;
                userToken = refreshToken;
                setLoginUser(userToken);
                setConnectionStatus(true);
                requestNewTokenBeforeExpiration(userToken);
                $rootScope.$broadcast('user_connected',sessionUser);
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
                if (debug) { console.debug('unauthorized: ' + JSON.stringify(msg.data)); }
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
                sessionUser.profile = payload.profile;
                sessionUser.orgId = payload.orgId;
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
                if (debug) { console.debug('Schedule to request a new token in ' + duration + ' seconds (token duration:' + initial + ')'); }
                tokenValidityTimeout = $timeout(function () {
                    if (debug) { console.debug('Time to request new token ' + initial); }
                    socket.emit('authenticate', { token: token });
                    // Note: If communication crashes right after we emitted and when servers is sending back the token,
                    // when the client reestablishes the connection, we would have to login because the previous token would be invalidated.
                }, duration * 1000);
            }
        }

        function retrieveToken() {
            var userToken = $location.search().token;
            if (userToken) {
                if (debug) { console.debug('Using token passed during redirection: ' + userToken); }
            } else {
                userToken = localStorage.token;
                if (userToken) {
                    if (debug) { console.debug('Using Token in local storage: ' + userToken); }
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
angular
    .module('socketio-auth')
    .provider('$socketio', socketioProvider);

function socketioProvider() {
    var debug;
    this.setDebug = function (value) {
        debug = value;
    };

    this.$get = ["$rootScope", "$q", "$auth", function socketioService($rootScope, $q, $auth) {

        return {
            on: on,
            emit: emit,
            logout: $auth.logout,
            fetch: fetch,
            post: post,
            notify: notify
        };

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
            if (debug) { console.debug('Fetching ' + operation + '...'); }
            return socketEmit(operation, data)
        }

        /**
         * notify is similar to fetch but more meaningful
         */
        function notify(operation, data) {
            if (debug) { console.debug('Notifying ' + operation + '...'); }
            return socketEmit(operation, data)
        }

        /**
         * post sends data to the server.
         * if data was already submitted, it would just return - which could happen when handling disconnection.
         * 
         */
        function post(operation, data) {
            if (debug) { console.debug('Posting ' + operation + '...'); }
            return socketEmit(operation, data);
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
                        if (debug) { console.debug('Error on ' + operation + ' ->' + JSON.stringify(result)); }
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
    }]
}
}());


//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFuZ3VsYXItc29ja2V0aW8uanMiLCIvc291cmNlL3NvY2tldC5tb2R1bGUuanMiLCIvc291cmNlL3NlcnZpY2VzL2F1dGguc2VydmljZS5qcyIsIi9zb3VyY2Uvc2VydmljZXMvc29ja2V0aW8uc2VydmljZS5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxDQUFDLFdBQVc7QUFDWjs7QUNEQSxRQUFBLE9BQUEsaUJBQUE7OztBRE1BLENBQUMsV0FBVztBQUNaOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUVhQTtLQUNBLE9BQUE7O0tBRUEsUUFBQSx5QkFBQSxVQUFBLE9BQUE7UUFDQSxPQUFBLE1BQUE7O0tBRUEsU0FBQSxTQUFBOztBQUVBLFNBQUEsZUFBQTs7SUFFQSxJQUFBLFVBQUEsV0FBQSxPQUFBLHNCQUFBOztJQUVBLEtBQUEsV0FBQSxVQUFBLE9BQUE7UUFDQSxRQUFBOzs7SUFHQSxLQUFBLGNBQUEsVUFBQSxPQUFBO1FBQ0EsV0FBQTs7O0lBR0EsS0FBQSxlQUFBLFVBQUEsT0FBQTtRQUNBLFlBQUE7OztJQUdBLEtBQUEsK0JBQUEsVUFBQSxPQUFBO1FBQ0Esc0JBQUEsUUFBQTs7O0lBR0EsS0FBQSxnRUFBQSxVQUFBLFlBQUEsV0FBQSxVQUFBLElBQUEsU0FBQTs7UUFFQSxJQUFBO1FBQ0EsSUFBQSxZQUFBO1FBQ0EsSUFBQSxjQUFBLEVBQUEsV0FBQTs7UUFFQSxJQUFBLENBQUEsV0FBQTs7Ozs7ZUFLQTtZQUNBLGFBQUEsUUFBQTs7UUFFQSxPQUFBO1lBQ0EsU0FBQTtZQUNBLFFBQUE7WUFDQSxnQkFBQTs7Ozs7O1FBTUEsU0FBQSxpQkFBQTs7WUFFQSxPQUFBOzs7Ozs7O1FBT0EsU0FBQSxVQUFBO1lBQ0EsSUFBQSxDQUFBLFFBQUE7Z0JBQ0E7O1lBRUEsT0FBQTs7O1FBR0EsU0FBQSxTQUFBOztZQUVBLElBQUEsUUFBQTtnQkFDQSxPQUFBLEtBQUEsVUFBQTs7OztRQUlBLFNBQUEsd0JBQUE7WUFDQSxJQUFBLFdBQUEsR0FBQTtZ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WUFBQTtZQUNBLE9BQUEsV0FBQSxXQUFBOzs7Ozs7OztRQVFBLFNBQUEsS0FBQSxXQUFBLE1BQUE7WUFDQSxJQUFBLE9BQUEsRUFBQSxRQUFBLE1BQUEsYUFBQSxZQUFBO1lBQ0EsT0FBQSxXQUFBLFdBQUE7OztRQUdBLFNBQUEsV0FBQSxXQUFBLE1BQUE7O1lBRUEsT0FBQSxNQUFBO2lCQUNBLEtBQUEscUJBQUE7Ozs7WUFJQSxTQUFBLG9CQUFBLFFBQUE7O2dCQUVBLElBQUEsV0FBQSxHQUFBO2dCQUNBLE9BQUEsS0FBQSxPQUFBLFdBQUEsTUFBQSxVQUFBLFFBQUE7b0JBQ0EsSUFBQSxPQUFBLE1BQUE7d0JBQ0EsSUFBQSxPQUFBLEVBQUEsUUFBQSxNQUFBLGNBQUEsWUFBQSxRQUFBLEtBQUEsVUFBQTt3QkFDQSxTQUFBLE9BQUEsRUFBQSxNQUFBLE9BQUEsTUFBQSxhQUFBLE9BQUE7O3lCQUVBO3dCQUNBLFNBQUEsUUFBQSxPQUFBOzs7Z0JBR0EsT0FBQSxTQUFBOzs7WUFHQSxTQUFBLGtCQUFBLEtBQUE7Z0JBQ0EsT0FBQSxHQUFBLE9BQUEsRUFBQSxNQUFBLGtCQUFBLGFBQUE7Ozs7Ozs7QUgrUkEiLCJmaWxlIjoiYW5ndWxhci1zb2NrZXRpby5qcyIsInNvdXJjZXNDb250ZW50IjpbIihmdW5jdGlvbigpIHtcblwidXNlIHN0cmljdFwiO1xuXG5hbmd1bGFyLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcsIFtdKTtcbn0oKSk7XG5cbihmdW5jdGlvbigpIHtcblwidXNlIHN0cmljdFwiO1xuXG4vKiogXG4gKiBUaGlzIHByb3ZpZGVyIGhhbmRsZXMgdGhlIGhhbmRzaGFrZSB0byBhdXRoZW50aWNhdGUgYSB1c2VyIGFuZCBtYWludGFpbiBhIHNlY3VyZSB3ZWIgc29ja2V0IGNvbm5lY3Rpb24gdmlhIHRva2Vucy5cbiAqIEl0IGFsc28gc2V0cyB0aGUgbG9naW4gYW5kIGxvZ291dCB1cmwgcGFydGljaXBhdGluZyBpbiB0aGUgYXV0aGVudGljYXRpb24uXG4gKiBcbiAqIFxuICogdXNhZ2UgZXhhbXBsZXM6XG4gKiBcbiAqIEluIHRoZSBjb25maWcgb2YgdGhlIGFwcCBtb2R1bGU6XG4gKiBzb2NrZXRTZXJ2aWNlUHJvdmlkZXIuc2V0TG9naW5VcmwoJy9hY2Nlc3MjL2xvZ2luJyk7XG4gKiBzb2NrZXRTZXJ2aWNlUHJvdmlkZXIuc2V0TG9nb3V0VXJsKCcvYWNjZXNzIy9sb2dpbicpO1xuICogc29ja2V0U2VydmljZVByb3ZpZGVyLnNldFJlY29ubmVjdGlvbk1heFRpbWVJblNlY3MoMTUpO1xuICogVGhpcyBkZWZpbmVzIGhvdyBtdWNoIHRpbWUgd2UgY2FuIHdhaXQgdG8gZXN0YWJsaXNoIGEgc3VjY2Vzc3VsIGNvbm5lY3Rpb24gYmVmb3JlIHJlamVjdGluZyB0aGUgY29ubmVjdGlvbiAoc29ja2V0U2VydmljZS5jb25uZWN0SU8pIHdpdGggYSB0aW1lb3V0LiBieSBkZWZhdWx0LCBpdCB3aWxsIHRyeSBmb3IgMTUgc2Vjb25kcyB0byBnZXQgYSBjb25uZWN0aW9uIGFuZCB0aGVuIGdpdmUgdXBcbiAqICBcbiAqIEJlZm9yZSBhbnkgc29ja2V0IHVzZSBpbiB5b3VyIHNlcnZpY2VzIG9yIHJlc29sdmUgYmxvY2tzLCBjb25uZWN0KCkgbWFrZXMgc3VyZSB0aGF0IHdlIGhhdmUgYW4gZXN0YWJsaXNoZWQgYXV0aGVudGljYXRlZCBjb25uZWN0aW9uIGJ5IHVzaW5nIHRoZSBmb2xsb3dpbmc6XG4gKiBzb2NrZXRTZXJ2aWNlLmNvbm5lY3QoKS50aGVuKFxuICogZnVuY3Rpb24oc29ja2V0KXsgLi4uIHNvY2tldC5lbWl0KCkuLiB9KS5jYXRjaChmdW5jdGlvbihlcnIpIHsuLi59KVxuICogXG4gKiBcbiAqL1xuYW5ndWxhclxuICAgIC5tb2R1bGUoJ3NvY2tldGlvLWF1dGgnKVxuICAgIC8vIGNvbnZlbmllbnQgc2VydmljZSByZXR1cm5pbmcgc2Vzc2lvblVzZXJcbiAgICAuZmFjdG9yeSgnc2Vzc2lvblVzZXInLCBmdW5jdGlvbiAoJGF1dGgpIHtcbiAgICAgICAgcmV0dXJuICRhdXRoLmdldFNlc3Npb25Vc2VyKCk7XG4gICAgfSlcbiAgICAucHJvdmlkZXIoJyRhdXRoJywgYXV0aFByb3ZpZGVyKTtcblxuZnVuY3Rpb24gYXV0aFByb3ZpZGVyKCkge1xuXG4gICAgdmFyIGxvZ2luVXJsLCBsb2dvdXRVcmwsIGRlYnVnLCByZWNvbm5lY3Rpb25NYXhUaW1lID0gMTU7XG5cbiAgICB0aGlzLnNldERlYnVnID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgIGRlYnVnID0gdmFsdWU7XG4gICAgfTtcblxuICAgIHRoaXMuc2V0TG9naW5VcmwgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgbG9naW5VcmwgPSB2YWx1ZTtcbiAgICB9O1xuXG4gICAgdGhpcy5zZXRMb2dvdXRVcmwgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgbG9nb3V0VXJsID0gdmFsdWU7XG4gICAgfTtcblxuICAgIHRoaXMuc2V0UmVjb25uZWN0aW9uTWF4VGltZUluU2VjcyA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICByZWNvbm5lY3Rpb25NYXhUaW1lID0gdmFsdWUgKiAxMDAwO1xuICAgIH07XG5cbiAgICB0aGlzLiRnZXQgPSBmdW5jdGlvbiAoJHJvb3RTY29wZSwgJGxvY2F0aW9uLCAkdGltZW91dCwgJHEsICR3aW5kb3cpIHtcblxuICAgICAgICB2YXIgc29ja2V0O1xuICAgICAgICB2YXIgdXNlclRva2VuID0gcmV0cmlldmVUb2tlbigpO1xuICAgICAgICB2YXIgc2Vzc2lvblVzZXIgPSB7IGNvbm5lY3RlZDogZmFsc2UgfTtcblxuICAgICAgICBpZiAoIXVzZXJUb2tlbikge1xuICAgICAgICAgICAgLy8gQFRPRE86IHRoaXMgcmlnaHQgd2F5IHRvIHJlZGlyZWN0IGlmIHdlIGhhdmUgbm8gdG9rZW4gd2hlbiB3ZSByZWZyZXNoIG9yIGhpdCB0aGUgYXBwLlxuICAgICAgICAgICAgLy8gIHJlZGlyZWN0KGxvZ2luVXJsKTtcbiAgICAgICAgICAgIC8vIGJ1dCBpdCB3b3VsZCBwcmV2ZW50IG1vc3QgdW5pdCB0ZXN0cyBmcm9tIHJ1bm5pbmcgYmVjYXVzZSB0aGlzIG1vZHVsZSBpcyB0aWdobHkgY291cGxlZCB3aXRoIGFsbCB1bml0IHRlc3RzIChkZXBlbmRzIG9uIGl0KWF0IHRoaXMgdGltZSA6XG5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGxvY2FsU3RvcmFnZS50b2tlbiA9IHVzZXJUb2tlbjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgY29ubmVjdDogY29ubmVjdCxcbiAgICAgICAgICAgIGxvZ291dDogbG9nb3V0LFxuICAgICAgICAgICAgZ2V0U2Vzc2lvblVzZXI6IGdldFNlc3Npb25Vc2VyXG4gICAgICAgIH07XG5cblxuICAgICAgICAvLy8vLy8vLy8vLy8vLy8vLy8vXG5cbiAgICAgICAgZnVuY3Rpb24gZ2V0U2Vzc2lvblVzZXIoKSB7XG4gICAgICAgICAgICAvLyB0aGUgb2JqZWN0IHdpbGwgaGF2ZSB0aGUgdXNlciBpbmZvcm1hdGlvbiB3aGVuIHRoZSBjb25uZWN0aW9uIGlzIGVzdGFibGlzaGVkLiBPdGhlcndpc2UgaXRzIGNvbm5lY3Rpb24gcHJvcGVydHkgd2lsbCBiZSBmYWxzZTsgXG4gICAgICAgICAgICByZXR1cm4gc2Vzc2lvblVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvKipcbiAgICAgICAgICogcmV0dXJucyBhIHByb21pc2UgXG4gICAgICAgICAqIHRoZSBzdWNjZXNzIGZ1bmN0aW9uIHJlY2VpdmVzIHRoZSBzb2NrZXQgYXMgYSBwYXJhbWV0ZXJcbiAgICAgICAgICovXG4gICAgICAgIGZ1bmN0aW9uIGNvbm5lY3QoKSB7XG4gICAgICAgICAgICBpZiAoIXNvY2tldCkge1xuICAgICAgICAgICAgICAgIHNldHVwKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZ2V0Rm9yVmFsaWRDb25uZWN0aW9uKCk7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBsb2dvdXQoKSB7XG4gICAgICAgICAgICAvLyBjb25uZWN0aW9uIGNvdWxkIGJlIGxvc3QgZHVyaW5nIGxvZ291dC4uc28gaXQgY291bGQgbWVhbiB3ZSBoYXZlIG5vdCBsb2dvdXQgb24gc2VydmVyIHNpZGUuXG4gICAgICAgICAgICBpZiAoc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2xvZ291dCcsIHVzZXJUb2tlbik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBnZXRGb3JWYWxpZENvbm5lY3Rpb24oKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuICAgICAgICAgICAgaWYgKHNlc3Npb25Vc2VyLmNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgLy8gYmVpbmcgdGhlIHNjZW5lLCBzb2NrZXQuaW8gaXMgdHJ5aW5nIHRvIHJlY29ubmVjdCBhbmQgYXV0aGVudGljYXRlIGlmIHRoZSBjb25uZWN0aW9uIHdhcyBsb3N0O1xuICAgICAgICAgICAgICAgIHJlY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHNvY2tldCk7XG4gICAgICAgICAgICAgICAgfSkuY2F0Y2goZnVuY3Rpb24gKGVycikge1xuICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoJ1VTRVJfTk9UX0NPTk5FQ1RFRCcpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZWNvbm5lY3QoKSB7XG4gICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuXG4gICAgICAgICAgICBpZiAoc2Vzc2lvblVzZXIuY29ubmVjdGVkKSB7XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy9AVE9ETyBUTyBUSElOSyBBQk9VVDosIGlmIHRoZSBzb2NrZXQgaXMgY29ubmVjdGluZyBhbHJlYWR5LCBtZWFucyB0aGF0IGEgY29ubmVjdCB3YXMgY2FsbGVkIGFscmVhZHkgYnkgYW5vdGhlciBhc3luYyBjYWxsLCBzbyBqdXN0IHdhaXQgZm9yIHVzZXJfY29ubmVjdGVkXG5cblxuXG4gICAgICAgICAgICAvLyBpZiB0aGUgcmVzcG9uc2UgZG9lcyBub3QgY29tZSBxdWljay4ubGV0J3MgZ2l2ZSB1cCBzbyB3ZSBkb24ndCBnZXQgc3R1Y2sgd2FpdGluZ1xuICAgICAgICAgICAgLy8gQFRPRE86b3RoZXIgd2F5IGlzIHRvIHdhdGNoIGZvciBhIGNvbm5lY3Rpb24gZXJyb3IuLi5cbiAgICAgICAgICAgIHZhciBhY2NlcHRhYmxlRGVsYXk7XG4gICAgICAgICAgICB2YXIgb2ZmID0gJHJvb3RTY29wZS4kb24oJ3VzZXJfY29ubmVjdGVkJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIG9mZigpO1xuICAgICAgICAgICAgICAgIGlmIChhY2NlcHRhYmxlRGVsYXkpIHtcbiAgICAgICAgICAgICAgICAgICAgJHRpbWVvdXQuY2FuY2VsKGFjY2VwdGFibGVEZWxheSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICBhY2NlcHRhYmxlRGVsYXkgPSAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgb2ZmKCk7XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KCdUSU1FT1VUJyk7XG4gICAgICAgICAgICB9LCByZWNvbm5lY3Rpb25NYXhUaW1lKTtcblxuICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBzZXR1cCgpIHtcbiAgICAgICAgICAgIGlmIChzb2NrZXQpIHtcbiAgICAgICAgICAgICAgICAvL2FscmVhZHkgY2FsbGVkLi4uXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdmFyIHRva2VuVmFsaWRpdHlUaW1lb3V0O1xuICAgICAgICAgICAgLy8gZXN0YWJsaXNoIGNvbm5lY3Rpb24gd2l0aG91dCBwYXNzaW5nIHRoZSB0b2tlbiAoc28gdGhhdCBpdCBpcyBub3QgdmlzaWJsZSBpbiB0aGUgbG9nKVxuICAgICAgICAgICAgc29ja2V0ID0gaW8uY29ubmVjdCh7XG4gICAgICAgICAgICAgICAgJ2ZvcmNlTmV3JzogdHJ1ZSxcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICBzb2NrZXRcbiAgICAgICAgICAgICAgICAub24oJ2Nvbm5lY3QnLCBvbkNvbm5lY3QpXG4gICAgICAgICAgICAgICAgLm9uKCdhdXRoZW50aWNhdGVkJywgb25BdXRoZW50aWNhdGVkKVxuICAgICAgICAgICAgICAgIC5vbigndW5hdXRob3JpemVkJywgb25VbmF1dGhvcml6ZWQpXG4gICAgICAgICAgICAgICAgLm9uKCdsb2dnZWRfb3V0Jywgb25Mb2dPdXQpXG4gICAgICAgICAgICAgICAgLm9uKCdkaXNjb25uZWN0Jywgb25EaXNjb25uZWN0KTtcblxuICAgICAgICAgICAgLy8gVE9ETzogdGhpcyBmb2xsb3dvd2luZyBldmVudCBpcyBzdGlsbCB1c2VkLj8/Py4uLi5cbiAgICAgICAgICAgIHNvY2tldFxuICAgICAgICAgICAgICAgIC5vbignY29ubmVjdF9lcnJvcicsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuICAgICAgICAgICAgZnVuY3Rpb24gb25Db25uZWN0KCkge1xuICAgICAgICAgICAgICAgIC8vIHRoZSBzb2NrZXQgaXMgY29ubmVjdGVkLCB0aW1lIHRvIHBhc3MgdGhlIHRva2VuIHRvIGF1dGhlbnRpY2F0ZSBhc2FwXG4gICAgICAgICAgICAgICAgLy8gYmVjYXVzZSB0aGUgdG9rZW4gaXMgYWJvdXQgdG8gZXhwaXJlLi4uaWYgaXQgZXhwaXJlcyB3ZSB3aWxsIGhhdmUgdG8gcmVsb2cgaW5cbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICBzb2NrZXQuZW1pdCgnYXV0aGVudGljYXRlJywgeyB0b2tlbjogdXNlclRva2VuIH0pOyAvLyBzZW5kIHRoZSBqd3RcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gb25EaXNjb25uZWN0KCkge1xuICAgICAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdTZXNzaW9uIGRpc2Nvbm5lY3RlZCcpOyB9XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KCd1c2VyX2Rpc2Nvbm5lY3RlZCcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkF1dGhlbnRpY2F0ZWQocmVmcmVzaFRva2VuKSB7XG4gICAgICAgICAgICAgICAgY2xlYXJUb2tlblRpbWVvdXQoKTtcbiAgICAgICAgICAgICAgICAvLyB0aGUgc2VydmVyIGNvbmZpcm1lZCB0aGF0IHRoZSB0b2tlbiBpcyB2YWxpZC4uLndlIGFyZSBnb29kIHRvIGdvXG4gICAgICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ2F1dGhlbnRpY2F0ZWQsIHJlY2VpdmVkIG5ldyB0b2tlbjogJyArIChyZWZyZXNoVG9rZW4gIT0gdXNlclRva2VuKSk7IH1cbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UudG9rZW4gPSByZWZyZXNoVG9rZW47XG4gICAgICAgICAgICAgICAgdXNlclRva2VuID0gcmVmcmVzaFRva2VuO1xuICAgICAgICAgICAgICAgIHNldExvZ2luVXNlcih1c2VyVG9rZW4pO1xuICAgICAgICAgICAgICAgIHNldENvbm5lY3Rpb25TdGF0dXModHJ1ZSk7XG4gICAgICAgICAgICAgICAgcmVxdWVzdE5ld1Rva2VuQmVmb3JlRXhwaXJhdGlvbih1c2VyVG9rZW4pO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdCgndXNlcl9jb25uZWN0ZWQnLHNlc3Npb25Vc2VyKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gb25Mb2dPdXQoKSB7XG4gICAgICAgICAgICAgICAgY2xlYXJUb2tlblRpbWVvdXQoKTtcbiAgICAgICAgICAgICAgICAvLyB0b2tlbiBpcyBubyBsb25nZXIgYXZhaWxhYmxlLlxuICAgICAgICAgICAgICAgIGRlbGV0ZSBsb2NhbFN0b3JhZ2UudG9rZW47XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgcmVkaXJlY3QobG9nb3V0VXJsIHx8IGxvZ2luVXJsKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gb25VbmF1dGhvcml6ZWQobXNnKSB7XG4gICAgICAgICAgICAgICAgY2xlYXJUb2tlblRpbWVvdXQoKTtcbiAgICAgICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygndW5hdXRob3JpemVkOiAnICsgSlNPTi5zdHJpbmdpZnkobXNnLmRhdGEpKTsgfVxuICAgICAgICAgICAgICAgIHNldENvbm5lY3Rpb25TdGF0dXMoZmFsc2UpO1xuICAgICAgICAgICAgICAgIHJlZGlyZWN0KGxvZ2luVXJsKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gc2V0Q29ubmVjdGlvblN0YXR1cyhjb25uZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5jb25uZWN0ZWQgPSBjb25uZWN0ZWQ7XG4gICAgICAgICAgICAgICAgLy9jb25zb2xlLmRlYnVnKFwiQ29ubmVjdGlvbiBzdGF0dXM6XCIgKyBKU09OLnN0cmluZ2lmeShzZXNzaW9uVXNlcikpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBzZXRMb2dpblVzZXIodG9rZW4pIHtcbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZCA9IGRlY29kZSh0b2tlbik7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIuaWQgPSBwYXlsb2FkLmlkO1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmRpc3BsYXkgPSBwYXlsb2FkLmRpc3BsYXk7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIuZmlyc3ROYW1lID0gcGF5bG9hZC5maXJzdE5hbWU7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIubGFzdE5hbWUgPSBwYXlsb2FkLmxhc3ROYW1lO1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLnJvbGUgPSBwYXlsb2FkLnJvbGU7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIucHJvZmlsZSA9IHBheWxvYWQucHJvZmlsZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gY2xlYXJUb2tlblRpbWVvdXQoKSB7XG4gICAgICAgICAgICAgICAgaWYgKHRva2VuVmFsaWRpdHlUaW1lb3V0KSB7XG4gICAgICAgICAgICAgICAgICAgICR0aW1lb3V0LmNhbmNlbCh0b2tlblZhbGlkaXR5VGltZW91dCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBkZWNvZGUodG9rZW4pIHtcbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0VXJsID0gdG9rZW4uc3BsaXQoJy4nKVsxXTtcbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0ID0gYmFzZTY0VXJsLnJlcGxhY2UoJy0nLCAnKycpLnJlcGxhY2UoJ18nLCAnLycpO1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gSlNPTi5wYXJzZSgkd2luZG93LmF0b2IoYmFzZTY0KSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHBheWxvYWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHJlcXVlc3ROZXdUb2tlbkJlZm9yZUV4cGlyYXRpb24odG9rZW4pIHtcbiAgICAgICAgICAgICAgICAvLyByZXF1ZXN0IGEgbGl0dGxlIGJlZm9yZS4uLlxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gZGVjb2RlKHRva2VuLCB7IGNvbXBsZXRlOiBmYWxzZSB9KTtcblxuICAgICAgICAgICAgICAgIHZhciBpbml0aWFsID0gcGF5bG9hZC5kdXI7XG5cbiAgICAgICAgICAgICAgICB2YXIgZHVyYXRpb24gPSAoaW5pdGlhbCAqIDkwIC8gMTAwKSB8IDA7XG4gICAgICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ1NjaGVkdWxlIHRvIHJlcXVlc3QgYSBuZXcgdG9rZW4gaW4gJyArIGR1cmF0aW9uICsgJyBzZWNvbmRzICh0b2tlbiBkdXJhdGlvbjonICsgaW5pdGlhbCArICcpJyk7IH1cbiAgICAgICAgICAgICAgICB0b2tlblZhbGlkaXR5VGltZW91dCA9ICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ1RpbWUgdG8gcmVxdWVzdCBuZXcgdG9rZW4gJyArIGluaXRpYWwpOyB9XG4gICAgICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KCdhdXRoZW50aWNhdGUnLCB7IHRva2VuOiB0b2tlbiB9KTtcbiAgICAgICAgICAgICAgICAgICAgLy8gTm90ZTogSWYgY29tbXVuaWNhdGlvbiBjcmFzaGVzIHJpZ2h0IGFmdGVyIHdlIGVtaXR0ZWQgYW5kIHdoZW4gc2VydmVycyBpcyBzZW5kaW5nIGJhY2sgdGhlIHRva2VuLFxuICAgICAgICAgICAgICAgICAgICAvLyB3aGVuIHRoZSBjbGllbnQgcmVlc3RhYmxpc2hlcyB0aGUgY29ubmVjdGlvbiwgd2Ugd291bGQgaGF2ZSB0byBsb2dpbiBiZWNhdXNlIHRoZSBwcmV2aW91cyB0b2tlbiB3b3VsZCBiZSBpbnZhbGlkYXRlZC5cbiAgICAgICAgICAgICAgICB9LCBkdXJhdGlvbiAqIDEwMDApO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gcmV0cmlldmVUb2tlbigpIHtcbiAgICAgICAgICAgIHZhciB1c2VyVG9rZW4gPSAkbG9jYXRpb24uc2VhcmNoKCkudG9rZW47XG4gICAgICAgICAgICBpZiAodXNlclRva2VuKSB7XG4gICAgICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ1VzaW5nIHRva2VuIHBhc3NlZCBkdXJpbmcgcmVkaXJlY3Rpb246ICcgKyB1c2VyVG9rZW4pOyB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHVzZXJUb2tlbiA9IGxvY2FsU3RvcmFnZS50b2tlbjtcbiAgICAgICAgICAgICAgICBpZiAodXNlclRva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdVc2luZyBUb2tlbiBpbiBsb2NhbCBzdG9yYWdlOiAnICsgdXNlclRva2VuKTsgfVxuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdXNlclRva2VuO1xuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gcmVkaXJlY3QodXJsKSB7XG4gICAgICAgICAgICB3aW5kb3cubG9jYXRpb24ucmVwbGFjZSh1cmwgfHwgJ2JhZFVybC5odG1sJyk7XG4gICAgICAgIH1cbiAgICB9O1xufVxufSgpKTtcblxuKGZ1bmN0aW9uKCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbi8qKiBcbiAqIFRoaXMgc2VydmljZSBhbGxvd3MgeW91ciBhcHBsaWNhdGlvbiBjb250YWN0IHRoZSB3ZWJzb2NrZXQgYXBpLlxuICogXG4gKiBJdCB3aWxsIGVuc3VyZSB0aGF0IHRoZSBjb25uZWN0aW9uIGlzIGF2YWlsYWJsZSBhbmQgdXNlciBpcyBhdXRoZW50aWNhdGVkIGJlZm9yZSBmZXRjaGluZyBkYXRhLlxuICogXG4gKi9cbmFuZ3VsYXJcbiAgICAubW9kdWxlKCdzb2NrZXRpby1hdXRoJylcbiAgICAucHJvdmlkZXIoJyRzb2NrZXRpbycsIHNvY2tldGlvUHJvdmlkZXIpO1xuXG5mdW5jdGlvbiBzb2NrZXRpb1Byb3ZpZGVyKCkge1xuICAgIHZhciBkZWJ1ZztcbiAgICB0aGlzLnNldERlYnVnID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgIGRlYnVnID0gdmFsdWU7XG4gICAgfTtcblxuICAgIHRoaXMuJGdldCA9IGZ1bmN0aW9uIHNvY2tldGlvU2VydmljZSgkcm9vdFNjb3BlLCAkcSwgJGF1dGgpIHtcblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgb246IG9uLFxuICAgICAgICAgICAgZW1pdDogZW1pdCxcbiAgICAgICAgICAgIGxvZ291dDogJGF1dGgubG9nb3V0LFxuICAgICAgICAgICAgZmV0Y2g6IGZldGNoLFxuICAgICAgICAgICAgcG9zdDogcG9zdCxcbiAgICAgICAgICAgIG5vdGlmeTogbm90aWZ5XG4gICAgICAgIH07XG5cbiAgICAgICAgLy8vLy8vLy8vLy8vLy8vLy8vL1xuICAgICAgICBmdW5jdGlvbiBvbihldmVudE5hbWUsIGNhbGxiYWNrKSB7XG4gICAgICAgICAgICAkYXV0aC5jb25uZWN0KCkudGhlbihmdW5jdGlvbiAoc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc29ja2V0Lm9uKGV2ZW50TmFtZSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgYXJncyA9IGFyZ3VtZW50cztcbiAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYXBwbHkoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2suYXBwbHkoc29ja2V0LCBhcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICAvLyBkZXByZWNhdGVkLCB1c2UgcG9zdC9ub3RpZnlcbiAgICAgICAgZnVuY3Rpb24gZW1pdChldmVudE5hbWUsIGRhdGEsIGNhbGxiYWNrKSB7XG4gICAgICAgICAgICAkYXV0aC5jb25uZWN0KCkudGhlbihmdW5jdGlvbiAoc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc29ja2V0LmVtaXQoZXZlbnROYW1lLCBkYXRhLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBhcmdzID0gYXJndW1lbnRzO1xuICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRhcHBseShmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoY2FsbGJhY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjay5hcHBseShzb2NrZXQsIGFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgLyoqXG4gICAgICAgICAqIGZldGNoIGRhdGEgdGhlIHdheSB3ZSBjYWxsIGFuIGFwaSBcbiAgICAgICAgICogaHR0cDovL3N0YWNrb3ZlcmZsb3cuY29tL3F1ZXN0aW9ucy8yMDY4NTIwOC93ZWJzb2NrZXQtdHJhbnNwb3J0LXJlbGlhYmlsaXR5LXNvY2tldC1pby1kYXRhLWxvc3MtZHVyaW5nLXJlY29ubmVjdGlvblxuICAgICAgICAgKiBcbiAgICAgICAgICovXG4gICAgICAgIGZ1bmN0aW9uIGZldGNoKG9wZXJhdGlvbiwgZGF0YSkge1xuICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ0ZldGNoaW5nICcgKyBvcGVyYXRpb24gKyAnLi4uJyk7IH1cbiAgICAgICAgICAgIHJldHVybiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSlcbiAgICAgICAgfVxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBub3RpZnkgaXMgc2ltaWxhciB0byBmZXRjaCBidXQgbW9yZSBtZWFuaW5nZnVsXG4gICAgICAgICAqL1xuICAgICAgICBmdW5jdGlvbiBub3RpZnkob3BlcmF0aW9uLCBkYXRhKSB7XG4gICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnTm90aWZ5aW5nICcgKyBvcGVyYXRpb24gKyAnLi4uJyk7IH1cbiAgICAgICAgICAgIHJldHVybiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSlcbiAgICAgICAgfVxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBwb3N0IHNlbmRzIGRhdGEgdG8gdGhlIHNlcnZlci5cbiAgICAgICAgICogaWYgZGF0YSB3YXMgYWxyZWFkeSBzdWJtaXR0ZWQsIGl0IHdvdWxkIGp1c3QgcmV0dXJuIC0gd2hpY2ggY291bGQgaGFwcGVuIHdoZW4gaGFuZGxpbmcgZGlzY29ubmVjdGlvbi5cbiAgICAgICAgICogXG4gICAgICAgICAqL1xuICAgICAgICBmdW5jdGlvbiBwb3N0KG9wZXJhdGlvbiwgZGF0YSkge1xuICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ1Bvc3RpbmcgJyArIG9wZXJhdGlvbiArICcuLi4nKTsgfVxuICAgICAgICAgICAgcmV0dXJuIHNvY2tldEVtaXQob3BlcmF0aW9uLCBkYXRhKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHNvY2tldEVtaXQob3BlcmF0aW9uLCBkYXRhKSB7XG5cbiAgICAgICAgICAgIHJldHVybiAkYXV0aC5jb25uZWN0KClcbiAgICAgICAgICAgICAgICAudGhlbihvbkNvbm5lY3Rpb25TdWNjZXNzLCBvbkNvbm5lY3Rpb25FcnJvcilcbiAgICAgICAgICAgICAgICA7Ly8gLmNhdGNoKG9uQ29ubmVjdGlvbkVycm9yKTtcblxuICAgICAgICAgICAgLy8vLy8vLy8vLy8vXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3Rpb25TdWNjZXNzKHNvY2tldCkge1xuICAgICAgICAgICAgICAgIC8vIGJ1dCB3aGF0IGlmIHdlIGhhdmUgbm90IGNvbm5lY3Rpb24gYmVmb3JlIHRoZSBlbWl0LCBpdCB3aWxsIHF1ZXVlIGNhbGwuLi5ub3Qgc28gZ29vZC4gICAgICAgIFxuICAgICAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG4gICAgICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2FwaScsIG9wZXJhdGlvbiwgZGF0YSwgZnVuY3Rpb24gKHJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgICBpZiAocmVzdWx0LmNvZGUpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdFcnJvciBvbiAnICsgb3BlcmF0aW9uICsgJyAtPicgKyBKU09OLnN0cmluZ2lmeShyZXN1bHQpKTsgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KHsgY29kZTogcmVzdWx0LmNvZGUsIGRlc2NyaXB0aW9uOiByZXN1bHQuZGF0YSB9KTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUocmVzdWx0LmRhdGEpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGRlZmVycmVkLnByb21pc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uQ29ubmVjdGlvbkVycm9yKGVycikge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBjb2RlOiAnQ09OTkVDVElPTl9FUlInLCBkZXNjcmlwdGlvbjogZXJyIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxufSgpKTtcblxuIiwiYW5ndWxhci5tb2R1bGUoJ3NvY2tldGlvLWF1dGgnLCBbXSk7XG4iLCJcbi8qKiBcbiAqIFRoaXMgcHJvdmlkZXIgaGFuZGxlcyB0aGUgaGFuZHNoYWtlIHRvIGF1dGhlbnRpY2F0ZSBhIHVzZXIgYW5kIG1haW50YWluIGEgc2VjdXJlIHdlYiBzb2NrZXQgY29ubmVjdGlvbiB2aWEgdG9rZW5zLlxuICogSXQgYWxzbyBzZXRzIHRoZSBsb2dpbiBhbmQgbG9nb3V0IHVybCBwYXJ0aWNpcGF0aW5nIGluIHRoZSBhdXRoZW50aWNhdGlvbi5cbiAqIFxuICogXG4gKiB1c2FnZSBleGFtcGxlczpcbiAqIFxuICogSW4gdGhlIGNvbmZpZyBvZiB0aGUgYXBwIG1vZHVsZTpcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRMb2dpblVybCgnL2FjY2VzcyMvbG9naW4nKTtcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRMb2dvdXRVcmwoJy9hY2Nlc3MjL2xvZ2luJyk7XG4gKiBzb2NrZXRTZXJ2aWNlUHJvdmlkZXIuc2V0UmVjb25uZWN0aW9uTWF4VGltZUluU2VjcygxNSk7XG4gKiBUaGlzIGRlZmluZXMgaG93IG11Y2ggdGltZSB3ZSBjYW4gd2FpdCB0byBlc3RhYmxpc2ggYSBzdWNjZXNzdWwgY29ubmVjdGlvbiBiZWZvcmUgcmVqZWN0aW5nIHRoZSBjb25uZWN0aW9uIChzb2NrZXRTZXJ2aWNlLmNvbm5lY3RJTykgd2l0aCBhIHRpbWVvdXQuIGJ5IGRlZmF1bHQsIGl0IHdpbGwgdHJ5IGZvciAxNSBzZWNvbmRzIHRvIGdldCBhIGNvbm5lY3Rpb24gYW5kIHRoZW4gZ2l2ZSB1cFxuICogIFxuICogQmVmb3JlIGFueSBzb2NrZXQgdXNlIGluIHlvdXIgc2VydmljZXMgb3IgcmVzb2x2ZSBibG9ja3MsIGNvbm5lY3QoKSBtYWtlcyBzdXJlIHRoYXQgd2UgaGF2ZSBhbiBlc3RhYmxpc2hlZCBhdXRoZW50aWNhdGVkIGNvbm5lY3Rpb24gYnkgdXNpbmcgdGhlIGZvbGxvd2luZzpcbiAqIHNvY2tldFNlcnZpY2UuY29ubmVjdCgpLnRoZW4oXG4gKiBmdW5jdGlvbihzb2NrZXQpeyAuLi4gc29ja2V0LmVtaXQoKS4uIH0pLmNhdGNoKGZ1bmN0aW9uKGVycikgey4uLn0pXG4gKiBcbiAqIFxuICovXG5hbmd1bGFyXG4gICAgLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcpXG4gICAgLy8gY29udmVuaWVudCBzZXJ2aWNlIHJldHVybmluZyBzZXNzaW9uVXNlclxuICAgIC5mYWN0b3J5KCdzZXNzaW9uVXNlcicsIGZ1bmN0aW9uICgkYXV0aCkge1xuICAgICAgICByZXR1cm4gJGF1dGguZ2V0U2Vzc2lvblVzZXIoKTtcbiAgICB9KVxuICAgIC5wcm92aWRlcignJGF1dGgnLCBhdXRoUHJvdmlkZXIpO1xuXG5mdW5jdGlvbiBhdXRoUHJvdmlkZXIoKSB7XG5cbiAgICB2YXIgbG9naW5VcmwsIGxvZ291dFVybCwgZGVidWcsIHJlY29ubmVjdGlvbk1heFRpbWUgPSAxNTtcblxuICAgIHRoaXMuc2V0RGVidWcgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgZGVidWcgPSB2YWx1ZTtcbiAgICB9O1xuXG4gICAgdGhpcy5zZXRMb2dpblVybCA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICBsb2dpblVybCA9IHZhbHVlO1xuICAgIH07XG5cbiAgICB0aGlzLnNldExvZ291dFVybCA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICBsb2dvdXRVcmwgPSB2YWx1ZTtcbiAgICB9O1xuXG4gICAgdGhpcy5zZXRSZWNvbm5lY3Rpb25NYXhUaW1lSW5TZWNzID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgIHJlY29ubmVjdGlvbk1heFRpbWUgPSB2YWx1ZSAqIDEwMDA7XG4gICAgfTtcblxuICAgIHRoaXMuJGdldCA9IGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkbG9jYXRpb24sICR0aW1lb3V0LCAkcSwgJHdpbmRvdykge1xuXG4gICAgICAgIHZhciBzb2NrZXQ7XG4gICAgICAgIHZhciB1c2VyVG9rZW4gPSByZXRyaWV2ZVRva2VuKCk7XG4gICAgICAgIHZhciBzZXNzaW9uVXNlciA9IHsgY29ubmVjdGVkOiBmYWxzZSB9O1xuXG4gICAgICAgIGlmICghdXNlclRva2VuKSB7XG4gICAgICAgICAgICAvLyBAVE9ETzogdGhpcyByaWdodCB3YXkgdG8gcmVkaXJlY3QgaWYgd2UgaGF2ZSBubyB0b2tlbiB3aGVuIHdlIHJlZnJlc2ggb3IgaGl0IHRoZSBhcHAuXG4gICAgICAgICAgICAvLyAgcmVkaXJlY3QobG9naW5VcmwpO1xuICAgICAgICAgICAgLy8gYnV0IGl0IHdvdWxkIHByZXZlbnQgbW9zdCB1bml0IHRlc3RzIGZyb20gcnVubmluZyBiZWNhdXNlIHRoaXMgbW9kdWxlIGlzIHRpZ2hseSBjb3VwbGVkIHdpdGggYWxsIHVuaXQgdGVzdHMgKGRlcGVuZHMgb24gaXQpYXQgdGhpcyB0aW1lIDpcblxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnRva2VuID0gdXNlclRva2VuO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBjb25uZWN0OiBjb25uZWN0LFxuICAgICAgICAgICAgbG9nb3V0OiBsb2dvdXQsXG4gICAgICAgICAgICBnZXRTZXNzaW9uVXNlcjogZ2V0U2Vzc2lvblVzZXJcbiAgICAgICAgfTtcblxuXG4gICAgICAgIC8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICAgICBmdW5jdGlvbiBnZXRTZXNzaW9uVXNlcigpIHtcbiAgICAgICAgICAgIC8vIHRoZSBvYmplY3Qgd2lsbCBoYXZlIHRoZSB1c2VyIGluZm9ybWF0aW9uIHdoZW4gdGhlIGNvbm5lY3Rpb24gaXMgZXN0YWJsaXNoZWQuIE90aGVyd2lzZSBpdHMgY29ubmVjdGlvbiBwcm9wZXJ0eSB3aWxsIGJlIGZhbHNlOyBcbiAgICAgICAgICAgIHJldHVybiBzZXNzaW9uVXNlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiByZXR1cm5zIGEgcHJvbWlzZSBcbiAgICAgICAgICogdGhlIHN1Y2Nlc3MgZnVuY3Rpb24gcmVjZWl2ZXMgdGhlIHNvY2tldCBhcyBhIHBhcmFtZXRlclxuICAgICAgICAgKi9cbiAgICAgICAgZnVuY3Rpb24gY29ubmVjdCgpIHtcbiAgICAgICAgICAgIGlmICghc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc2V0dXAoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBnZXRGb3JWYWxpZENvbm5lY3Rpb24oKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgICAgICAgIC8vIGNvbm5lY3Rpb24gY291bGQgYmUgbG9zdCBkdXJpbmcgbG9nb3V0Li5zbyBpdCBjb3VsZCBtZWFuIHdlIGhhdmUgbm90IGxvZ291dCBvbiBzZXJ2ZXIgc2lkZS5cbiAgICAgICAgICAgIGlmIChzb2NrZXQpIHtcbiAgICAgICAgICAgICAgICBzb2NrZXQuZW1pdCgnbG9nb3V0JywgdXNlclRva2VuKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIGdldEZvclZhbGlkQ29ubmVjdGlvbigpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG4gICAgICAgICAgICBpZiAoc2Vzc2lvblVzZXIuY29ubmVjdGVkKSB7XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAvLyBiZWluZyB0aGUgc2NlbmUsIHNvY2tldC5pbyBpcyB0cnlpbmcgdG8gcmVjb25uZWN0IGFuZCBhdXRoZW50aWNhdGUgaWYgdGhlIGNvbm5lY3Rpb24gd2FzIGxvc3Q7XG4gICAgICAgICAgICAgICAgcmVjb25uZWN0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgICAgICB9KS5jYXRjaChmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlamVjdCgnVVNFUl9OT1RfQ09OTkVDVEVEJyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHJlY29ubmVjdCgpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAgIGlmIChzZXNzaW9uVXNlci5jb25uZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHNvY2tldCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvL0BUT0RPIFRPIFRISU5LIEFCT1VUOiwgaWYgdGhlIHNvY2tldCBpcyBjb25uZWN0aW5nIGFscmVhZHksIG1lYW5zIHRoYXQgYSBjb25uZWN0IHdhcyBjYWxsZWQgYWxyZWFkeSBieSBhbm90aGVyIGFzeW5jIGNhbGwsIHNvIGp1c3Qgd2FpdCBmb3IgdXNlcl9jb25uZWN0ZWRcblxuXG5cbiAgICAgICAgICAgIC8vIGlmIHRoZSByZXNwb25zZSBkb2VzIG5vdCBjb21lIHF1aWNrLi5sZXQncyBnaXZlIHVwIHNvIHdlIGRvbid0IGdldCBzdHVjayB3YWl0aW5nXG4gICAgICAgICAgICAvLyBAVE9ETzpvdGhlciB3YXkgaXMgdG8gd2F0Y2ggZm9yIGEgY29ubmVjdGlvbiBlcnJvci4uLlxuICAgICAgICAgICAgdmFyIGFjY2VwdGFibGVEZWxheTtcbiAgICAgICAgICAgIHZhciBvZmYgPSAkcm9vdFNjb3BlLiRvbigndXNlcl9jb25uZWN0ZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgb2ZmKCk7XG4gICAgICAgICAgICAgICAgaWYgKGFjY2VwdGFibGVEZWxheSkge1xuICAgICAgICAgICAgICAgICAgICAkdGltZW91dC5jYW5jZWwoYWNjZXB0YWJsZURlbGF5KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIGFjY2VwdGFibGVEZWxheSA9ICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBvZmYoKTtcbiAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoJ1RJTUVPVVQnKTtcbiAgICAgICAgICAgIH0sIHJlY29ubmVjdGlvbk1heFRpbWUpO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHNldHVwKCkge1xuICAgICAgICAgICAgaWYgKHNvY2tldCkge1xuICAgICAgICAgICAgICAgIC8vYWxyZWFkeSBjYWxsZWQuLi5cbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB2YXIgdG9rZW5WYWxpZGl0eVRpbWVvdXQ7XG4gICAgICAgICAgICAvLyBlc3RhYmxpc2ggY29ubmVjdGlvbiB3aXRob3V0IHBhc3NpbmcgdGhlIHRva2VuIChzbyB0aGF0IGl0IGlzIG5vdCB2aXNpYmxlIGluIHRoZSBsb2cpXG4gICAgICAgICAgICBzb2NrZXQgPSBpby5jb25uZWN0KHtcbiAgICAgICAgICAgICAgICAnZm9yY2VOZXcnOiB0cnVlLFxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNvY2tldFxuICAgICAgICAgICAgICAgIC5vbignY29ubmVjdCcsIG9uQ29ubmVjdClcbiAgICAgICAgICAgICAgICAub24oJ2F1dGhlbnRpY2F0ZWQnLCBvbkF1dGhlbnRpY2F0ZWQpXG4gICAgICAgICAgICAgICAgLm9uKCd1bmF1dGhvcml6ZWQnLCBvblVuYXV0aG9yaXplZClcbiAgICAgICAgICAgICAgICAub24oJ2xvZ2dlZF9vdXQnLCBvbkxvZ091dClcbiAgICAgICAgICAgICAgICAub24oJ2Rpc2Nvbm5lY3QnLCBvbkRpc2Nvbm5lY3QpO1xuXG4gICAgICAgICAgICAvLyBUT0RPOiB0aGlzIGZvbGxvd293aW5nIGV2ZW50IGlzIHN0aWxsIHVzZWQuPz8/Li4uLlxuICAgICAgICAgICAgc29ja2V0XG4gICAgICAgICAgICAgICAgLm9uKCdjb25uZWN0X2Vycm9yJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3QoKSB7XG4gICAgICAgICAgICAgICAgLy8gdGhlIHNvY2tldCBpcyBjb25uZWN0ZWQsIHRpbWUgdG8gcGFzcyB0aGUgdG9rZW4gdG8gYXV0aGVudGljYXRlIGFzYXBcbiAgICAgICAgICAgICAgICAvLyBiZWNhdXNlIHRoZSB0b2tlbiBpcyBhYm91dCB0byBleHBpcmUuLi5pZiBpdCBleHBpcmVzIHdlIHdpbGwgaGF2ZSB0byByZWxvZyBpblxuICAgICAgICAgICAgICAgIHNldENvbm5lY3Rpb25TdGF0dXMoZmFsc2UpO1xuICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KCdhdXRoZW50aWNhdGUnLCB7IHRva2VuOiB1c2VyVG9rZW4gfSk7IC8vIHNlbmQgdGhlIGp3dFxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkRpc2Nvbm5lY3QoKSB7XG4gICAgICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ1Nlc3Npb24gZGlzY29ubmVjdGVkJyk7IH1cbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoJ3VzZXJfZGlzY29ubmVjdGVkJyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uQXV0aGVudGljYXRlZChyZWZyZXNoVG9rZW4pIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIC8vIHRoZSBzZXJ2ZXIgY29uZmlybWVkIHRoYXQgdGhlIHRva2VuIGlzIHZhbGlkLi4ud2UgYXJlIGdvb2QgdG8gZ29cbiAgICAgICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnYXV0aGVudGljYXRlZCwgcmVjZWl2ZWQgbmV3IHRva2VuOiAnICsgKHJlZnJlc2hUb2tlbiAhPSB1c2VyVG9rZW4pKTsgfVxuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS50b2tlbiA9IHJlZnJlc2hUb2tlbjtcbiAgICAgICAgICAgICAgICB1c2VyVG9rZW4gPSByZWZyZXNoVG9rZW47XG4gICAgICAgICAgICAgICAgc2V0TG9naW5Vc2VyKHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyh0cnVlKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0TmV3VG9rZW5CZWZvcmVFeHBpcmF0aW9uKHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KCd1c2VyX2Nvbm5lY3RlZCcsc2Vzc2lvblVzZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkxvZ091dCgpIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIC8vIHRva2VuIGlzIG5vIGxvbmdlciBhdmFpbGFibGUuXG4gICAgICAgICAgICAgICAgZGVsZXRlIGxvY2FsU3RvcmFnZS50b2tlbjtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICByZWRpcmVjdChsb2dvdXRVcmwgfHwgbG9naW5VcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvblVuYXV0aG9yaXplZChtc2cpIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCd1bmF1dGhvcml6ZWQ6ICcgKyBKU09OLnN0cmluZ2lmeShtc2cuZGF0YSkpOyB9XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgcmVkaXJlY3QobG9naW5VcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBzZXRDb25uZWN0aW9uU3RhdHVzKGNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmNvbm5lY3RlZCA9IGNvbm5lY3RlZDtcbiAgICAgICAgICAgICAgICAvL2NvbnNvbGUuZGVidWcoXCJDb25uZWN0aW9uIHN0YXR1czpcIiArIEpTT04uc3RyaW5naWZ5KHNlc3Npb25Vc2VyKSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHNldExvZ2luVXNlcih0b2tlbikge1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gZGVjb2RlKHRva2VuKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5pZCA9IHBheWxvYWQuaWQ7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIuZGlzcGxheSA9IHBheWxvYWQuZGlzcGxheTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5maXJzdE5hbWUgPSBwYXlsb2FkLmZpcnN0TmFtZTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5sYXN0TmFtZSA9IHBheWxvYWQubGFzdE5hbWU7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIucm9sZSA9IHBheWxvYWQucm9sZTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5wcm9maWxlID0gcGF5bG9hZC5wcm9maWxlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBjbGVhclRva2VuVGltZW91dCgpIHtcbiAgICAgICAgICAgICAgICBpZiAodG9rZW5WYWxpZGl0eVRpbWVvdXQpIHtcbiAgICAgICAgICAgICAgICAgICAgJHRpbWVvdXQuY2FuY2VsKHRva2VuVmFsaWRpdHlUaW1lb3V0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIGRlY29kZSh0b2tlbikge1xuICAgICAgICAgICAgICAgIHZhciBiYXNlNjRVcmwgPSB0b2tlbi5zcGxpdCgnLicpWzFdO1xuICAgICAgICAgICAgICAgIHZhciBiYXNlNjQgPSBiYXNlNjRVcmwucmVwbGFjZSgnLScsICcrJykucmVwbGFjZSgnXycsICcvJyk7XG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWQgPSBKU09OLnBhcnNlKCR3aW5kb3cuYXRvYihiYXNlNjQpKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcGF5bG9hZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gcmVxdWVzdE5ld1Rva2VuQmVmb3JlRXhwaXJhdGlvbih0b2tlbikge1xuICAgICAgICAgICAgICAgIC8vIHJlcXVlc3QgYSBsaXR0bGUgYmVmb3JlLi4uXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWQgPSBkZWNvZGUodG9rZW4sIHsgY29tcGxldGU6IGZhbHNlIH0pO1xuXG4gICAgICAgICAgICAgICAgdmFyIGluaXRpYWwgPSBwYXlsb2FkLmR1cjtcblxuICAgICAgICAgICAgICAgIHZhciBkdXJhdGlvbiA9IChpbml0aWFsICogOTAgLyAxMDApIHwgMDtcbiAgICAgICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnU2NoZWR1bGUgdG8gcmVxdWVzdCBhIG5ldyB0b2tlbiBpbiAnICsgZHVyYXRpb24gKyAnIHNlY29uZHMgKHRva2VuIGR1cmF0aW9uOicgKyBpbml0aWFsICsgJyknKTsgfVxuICAgICAgICAgICAgICAgIHRva2VuVmFsaWRpdHlUaW1lb3V0ID0gJHRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnVGltZSB0byByZXF1ZXN0IG5ldyB0b2tlbiAnICsgaW5pdGlhbCk7IH1cbiAgICAgICAgICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2F1dGhlbnRpY2F0ZScsIHsgdG9rZW46IHRva2VuIH0pO1xuICAgICAgICAgICAgICAgICAgICAvLyBOb3RlOiBJZiBjb21tdW5pY2F0aW9uIGNyYXNoZXMgcmlnaHQgYWZ0ZXIgd2UgZW1pdHRlZCBhbmQgd2hlbiBzZXJ2ZXJzIGlzIHNlbmRpbmcgYmFjayB0aGUgdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgIC8vIHdoZW4gdGhlIGNsaWVudCByZWVzdGFibGlzaGVzIHRoZSBjb25uZWN0aW9uLCB3ZSB3b3VsZCBoYXZlIHRvIGxvZ2luIGJlY2F1c2UgdGhlIHByZXZpb3VzIHRva2VuIHdvdWxkIGJlIGludmFsaWRhdGVkLlxuICAgICAgICAgICAgICAgIH0sIGR1cmF0aW9uICogMTAwMCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZXRyaWV2ZVRva2VuKCkge1xuICAgICAgICAgICAgdmFyIHVzZXJUb2tlbiA9ICRsb2NhdGlvbi5zZWFyY2goKS50b2tlbjtcbiAgICAgICAgICAgIGlmICh1c2VyVG9rZW4pIHtcbiAgICAgICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnVXNpbmcgdG9rZW4gcGFzc2VkIGR1cmluZyByZWRpcmVjdGlvbjogJyArIHVzZXJUb2tlbik7IH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgdXNlclRva2VuID0gbG9jYWxTdG9yYWdlLnRva2VuO1xuICAgICAgICAgICAgICAgIGlmICh1c2VyVG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ1VzaW5nIFRva2VuIGluIGxvY2FsIHN0b3JhZ2U6ICcgKyB1c2VyVG9rZW4pOyB9XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcblxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB1c2VyVG9rZW47XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZWRpcmVjdCh1cmwpIHtcbiAgICAgICAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZXBsYWNlKHVybCB8fCAnYmFkVXJsLmh0bWwnKTtcbiAgICAgICAgfVxuICAgIH07XG59XG5cbiIsIlxuLyoqIFxuICogVGhpcyBzZXJ2aWNlIGFsbG93cyB5b3VyIGFwcGxpY2F0aW9uIGNvbnRhY3QgdGhlIHdlYnNvY2tldCBhcGkuXG4gKiBcbiAqIEl0IHdpbGwgZW5zdXJlIHRoYXQgdGhlIGNvbm5lY3Rpb24gaXMgYXZhaWxhYmxlIGFuZCB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQgYmVmb3JlIGZldGNoaW5nIGRhdGEuXG4gKiBcbiAqL1xuYW5ndWxhclxuICAgIC5tb2R1bGUoJ3NvY2tldGlvLWF1dGgnKVxuICAgIC5wcm92aWRlcignJHNvY2tldGlvJywgc29ja2V0aW9Qcm92aWRlcik7XG5cbmZ1bmN0aW9uIHNvY2tldGlvUHJvdmlkZXIoKSB7XG4gICAgdmFyIGRlYnVnO1xuICAgIHRoaXMuc2V0RGVidWcgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgZGVidWcgPSB2YWx1ZTtcbiAgICB9O1xuXG4gICAgdGhpcy4kZ2V0ID0gZnVuY3Rpb24gc29ja2V0aW9TZXJ2aWNlKCRyb290U2NvcGUsICRxLCAkYXV0aCkge1xuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBvbjogb24sXG4gICAgICAgICAgICBlbWl0OiBlbWl0LFxuICAgICAgICAgICAgbG9nb3V0OiAkYXV0aC5sb2dvdXQsXG4gICAgICAgICAgICBmZXRjaDogZmV0Y2gsXG4gICAgICAgICAgICBwb3N0OiBwb3N0LFxuICAgICAgICAgICAgbm90aWZ5OiBub3RpZnlcbiAgICAgICAgfTtcblxuICAgICAgICAvLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgICAgIGZ1bmN0aW9uIG9uKGV2ZW50TmFtZSwgY2FsbGJhY2spIHtcbiAgICAgICAgICAgICRhdXRoLmNvbm5lY3QoKS50aGVuKGZ1bmN0aW9uIChzb2NrZXQpIHtcbiAgICAgICAgICAgICAgICBzb2NrZXQub24oZXZlbnROYW1lLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBhcmdzID0gYXJndW1lbnRzO1xuICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRhcHBseShmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjay5hcHBseShzb2NrZXQsIGFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIC8vIGRlcHJlY2F0ZWQsIHVzZSBwb3N0L25vdGlmeVxuICAgICAgICBmdW5jdGlvbiBlbWl0KGV2ZW50TmFtZSwgZGF0YSwgY2FsbGJhY2spIHtcbiAgICAgICAgICAgICRhdXRoLmNvbm5lY3QoKS50aGVuKGZ1bmN0aW9uIChzb2NrZXQpIHtcbiAgICAgICAgICAgICAgICBzb2NrZXQuZW1pdChldmVudE5hbWUsIGRhdGEsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7XG4gICAgICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGFwcGx5KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChjYWxsYmFjaykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrLmFwcGx5KHNvY2tldCwgYXJncyk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICAvKipcbiAgICAgICAgICogZmV0Y2ggZGF0YSB0aGUgd2F5IHdlIGNhbGwgYW4gYXBpIFxuICAgICAgICAgKiBodHRwOi8vc3RhY2tvdmVyZmxvdy5jb20vcXVlc3Rpb25zLzIwNjg1MjA4L3dlYnNvY2tldC10cmFuc3BvcnQtcmVsaWFiaWxpdHktc29ja2V0LWlvLWRhdGEtbG9zcy1kdXJpbmctcmVjb25uZWN0aW9uXG4gICAgICAgICAqIFxuICAgICAgICAgKi9cbiAgICAgICAgZnVuY3Rpb24gZmV0Y2gob3BlcmF0aW9uLCBkYXRhKSB7XG4gICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnRmV0Y2hpbmcgJyArIG9wZXJhdGlvbiArICcuLi4nKTsgfVxuICAgICAgICAgICAgcmV0dXJuIHNvY2tldEVtaXQob3BlcmF0aW9uLCBkYXRhKVxuICAgICAgICB9XG5cbiAgICAgICAgLyoqXG4gICAgICAgICAqIG5vdGlmeSBpcyBzaW1pbGFyIHRvIGZldGNoIGJ1dCBtb3JlIG1lYW5pbmdmdWxcbiAgICAgICAgICovXG4gICAgICAgIGZ1bmN0aW9uIG5vdGlmeShvcGVyYXRpb24sIGRhdGEpIHtcbiAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdOb3RpZnlpbmcgJyArIG9wZXJhdGlvbiArICcuLi4nKTsgfVxuICAgICAgICAgICAgcmV0dXJuIHNvY2tldEVtaXQob3BlcmF0aW9uLCBkYXRhKVxuICAgICAgICB9XG5cbiAgICAgICAgLyoqXG4gICAgICAgICAqIHBvc3Qgc2VuZHMgZGF0YSB0byB0aGUgc2VydmVyLlxuICAgICAgICAgKiBpZiBkYXRhIHdhcyBhbHJlYWR5IHN1Ym1pdHRlZCwgaXQgd291bGQganVzdCByZXR1cm4gLSB3aGljaCBjb3VsZCBoYXBwZW4gd2hlbiBoYW5kbGluZyBkaXNjb25uZWN0aW9uLlxuICAgICAgICAgKiBcbiAgICAgICAgICovXG4gICAgICAgIGZ1bmN0aW9uIHBvc3Qob3BlcmF0aW9uLCBkYXRhKSB7XG4gICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnUG9zdGluZyAnICsgb3BlcmF0aW9uICsgJy4uLicpOyB9XG4gICAgICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpO1xuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpIHtcblxuICAgICAgICAgICAgcmV0dXJuICRhdXRoLmNvbm5lY3QoKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uQ29ubmVjdGlvblN1Y2Nlc3MsIG9uQ29ubmVjdGlvbkVycm9yKVxuICAgICAgICAgICAgICAgIDsvLyAuY2F0Y2gob25Db25uZWN0aW9uRXJyb3IpO1xuXG4gICAgICAgICAgICAvLy8vLy8vLy8vLy9cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uQ29ubmVjdGlvblN1Y2Nlc3Moc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgLy8gYnV0IHdoYXQgaWYgd2UgaGF2ZSBub3QgY29ubmVjdGlvbiBiZWZvcmUgdGhlIGVtaXQsIGl0IHdpbGwgcXVldWUgY2FsbC4uLm5vdCBzbyBnb29kLiAgICAgICAgXG4gICAgICAgICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcbiAgICAgICAgICAgICAgICBzb2NrZXQuZW1pdCgnYXBpJywgb3BlcmF0aW9uLCBkYXRhLCBmdW5jdGlvbiAocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChyZXN1bHQuY29kZSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ0Vycm9yIG9uICcgKyBvcGVyYXRpb24gKyAnIC0+JyArIEpTT04uc3RyaW5naWZ5KHJlc3VsdCkpOyB9XG4gICAgICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoeyBjb2RlOiByZXN1bHQuY29kZSwgZGVzY3JpcHRpb246IHJlc3VsdC5kYXRhIH0pO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXN1bHQuZGF0YSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gb25Db25uZWN0aW9uRXJyb3IoZXJyKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IGNvZGU6ICdDT05ORUNUSU9OX0VSUicsIGRlc2NyaXB0aW9uOiBlcnIgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG5cbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
