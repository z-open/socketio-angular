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
                return _.assign(sessionUser,payload);
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

//# sourceMappingURL=data:application/json;charset=utf8;base64,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UUFBQSxNQUFBLG1CQUFBLEtBQUEsVUFBQSxJQUFBO2dCQUNBLG9CQUFBO2dCQUNBLFNBQUE7OztZQUdBLFNBQUEsb0JBQUEsV0FBQTtnQkFDQSxZQUFBLFlBQUE7Ozs7WUFJQSxTQUFBLGFBQUEsT0FBQTtnQkFDQSxJQUFBLFVBQUEsT0FBQTtnQkFDQSxPQUFBLEVBQUEsT0FBQSxZQUFBOzs7WUFHQSxTQUFBLG9CQUFBO2dCQUNBLElBQUEsc0JBQUE7b0JBQ0EsU0FBQSxPQUFBOzs7O1lBSUEsU0FBQSxPQUFBLE9BQUE7Z0JBQ0EsSUFBQSxZQUFBLE1BQUEsTUFBQSxLQUFBO2dCQUNBLElBQUEsU0FBQSxVQUFBLFFBQUEsS0FBQSxLQUFBLFFBQUEsS0FBQTtnQkFDQSxJQUFBLFVBQUEsS0FBQSxNQUFBLFFBQUEsS0FBQTtnQkFDQSxPQUFBOzs7WUFHQSxTQUFBLGdDQUFBLE9BQUE7O2dCQUVBLElBQUEsVUFBQSxPQUFBLE9BQUEsRUFBQSxVQUFBOztnQkFFQSxJQUFBLFVBQUEsUUFBQTs7Z0JBRUEsSUFBQSxXQUFBLENBQUEsVUFBQSxLQUFBLE9BQUE7Z0JBQ0EsSUFBQSxPQUFBLEVBQUEsUUFBQSxNQUFBLHdDQUFBLFdBQUEsOEJBQUEsVUFBQTtnQkFDQSx1QkFBQSxTQUFBLFlBQUE7b0JBQ0EsSUFBQSxPQUFBLEVBQUEsUUFBQSxNQUFBLCtCQUFBO29CQUNBLE9BQUEsS0FBQSxnQkFBQSxFQUFBLE9BQUE7OzttQkFHQSxXQUFBOzs7O1FBSUEsU0FBQSxnQkFBQTtZQUNBLElBQUEsWUFBQSxVQUFBLFNBQUE7WUFDQSxJQUFBLFdBQUE7Z0JBQ0EsSUFBQSxPQUFBLEVBQUEsUUFBQSxNQUFBLDRDQUFBO21CQUNBO2dCQUNBLFlBQUEsYUFBQTtnQkFDQSxJQUFBLFdBQUE7b0JBQ0EsSUFBQSxPQUFBLEVBQUEsUUFBQSxNQUFBLG1DQUFBO3VCQUNBOzs7O1lBSUEsT0FBQTs7O1FBR0EsU0FBQSxTQUFBLEtBQUE7WUFDQSxPQUFBLFNBQUEsUUFBQSxPQUFBOzs7Ozs7QUFNQSxDQUFBLFdBQUE7QUFDQTs7Ozs7Ozs7QUFRQTtLQUNBLE9BQUE7S0FDQSxTQUFBLGFBQUE7O0FBRUEsU0FBQSxtQkFBQTtJQUNBLElBQUE7SUFDQSxLQUFBLFdBQUEsVUFBQSxPQUFBO1FBQ0EsUUFBQTs7O0lBR0EsS0FBQSxxQ0FBQSxTQUFBLGdCQUFBLFlBQUEsSUFBQSxPQUFBOztRQUVBLE9BQUE7WUFDQSxJQUFBO1lBQ0EsTUFBQTtZQUNBLFFBQUEsTUFBQTtZQUNBLE9BQUE7WUFDQSxNQUFBO1lBQ0EsUUFBQTs7OztRQUlBLFNBQUEsR0FBQSxXQUFBLFVBQUE7WUFDQSxNQUFBLFVBQUEsS0FBQSxVQUFBLFFBQUE7Z0JBQ0EsT0FBQSxHQUFBLFdBQUEsWUFBQTtvQkFDQSxJQUFBLE9BQUE7b0JBQ0EsV0FBQSxPQUFBLFlBQUE7d0JBQ0EsU0FBQSxNQUFBLFFBQUE7Ozs7OztRQU1BLFNBQUEsS0FBQSxXQUFBLE1BQUEsVUFBQTtZQUNBLE1BQUEsVUFBQSxLQUFBLFVBQUEsUUFBQTtnQkFDQSxPQUFBLEtBQUEsV0FBQSxNQUFBLFlBQUE7b0JBQ0EsSUFBQSxPQUFBO29CQUNBLFdBQUEsT0FBQSxZQUFBO3dCQUNBLElBQUEsVUFBQTs0QkFDQSxTQUFBLE1BQUEsUUFBQTs7Ozs7Ozs7Ozs7O1FBWUEsU0FBQSxNQUFBLFdBQUEsTUFBQTtZQUNBLElBQUEsT0FBQSxFQUFBLFFBQUEsTUFBQSxjQUFBLFlBQUE7WUFDQSxPQUFBLFdBQUEsV0FBQTs7Ozs7O1FBTUEsU0FBQSxPQUFBLFdBQUEsTUFBQTtZQUNBLElBQUEsT0FBQSxFQUFBLFFBQUEsTUFBQSxlQUFBLFlBQUE7WUFDQSxPQUFBLFdBQUEsV0FBQTs7Ozs7Ozs7UUFRQSxTQUFBLEtBQUEsV0FBQSxNQUFBO1lBQ0EsSUFBQSxPQUFBLEVBQUEsUUFBQSxNQUFBLGFBQUEsWUFBQTtZQUNBLE9BQUEsV0FBQSxXQUFBOzs7UUFHQSxTQUFBLFdBQUEsV0FBQSxNQUFBOztZQUVBLE9BQUEsTUFBQTtpQkFDQSxLQUFBLHFCQUFBOzs7O1lBSUEsU0FBQSxvQkFBQSxRQUFBOztnQkFFQSxJQUFBLFdBQUEsR0FBQTtnQkFDQSxPQUFBLEtBQUEsT0FBQSxXQUFBLE1BQUEsVUFBQSxRQUFBO29CQUNBLElBQUEsT0FBQSxNQUFBO3dCQUNBLElBQUEsT0FBQSxFQUFBLFFBQUEsTUFBQSxjQUFBLFlBQUEsUUFBQSxLQUFBLFVBQUE7d0JBQ0EsU0FBQSxPQUFBLEVBQUEsTUFBQSxPQUFBLE1BQUEsYUFBQSxPQUFBOzt5QkFFQTt3QkFDQSxTQUFBLFFBQUEsT0FBQTs7O2dCQUdBLE9BQUEsU0FBQTs7O1lBR0EsU0FBQSxrQkFBQSxLQUFBO2dCQUNBLE9BQUEsR0FBQSxPQUFBLEVBQUEsTUFBQSxrQkFBQSxhQUFBOzs7Ozs7QUFNQSIsImZpbGUiOiJhbmd1bGFyLXNvY2tldGlvLmpzIiwic291cmNlc0NvbnRlbnQiOlsiKGZ1bmN0aW9uKCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbmFuZ3VsYXIubW9kdWxlKCdzb2NrZXRpby1hdXRoJywgW10pO1xufSgpKTtcblxuKGZ1bmN0aW9uKCkge1xuXCJ1c2Ugc3RyaWN0XCI7XG5cbi8qKiBcbiAqIFRoaXMgcHJvdmlkZXIgaGFuZGxlcyB0aGUgaGFuZHNoYWtlIHRvIGF1dGhlbnRpY2F0ZSBhIHVzZXIgYW5kIG1haW50YWluIGEgc2VjdXJlIHdlYiBzb2NrZXQgY29ubmVjdGlvbiB2aWEgdG9rZW5zLlxuICogSXQgYWxzbyBzZXRzIHRoZSBsb2dpbiBhbmQgbG9nb3V0IHVybCBwYXJ0aWNpcGF0aW5nIGluIHRoZSBhdXRoZW50aWNhdGlvbi5cbiAqIFxuICogXG4gKiB1c2FnZSBleGFtcGxlczpcbiAqIFxuICogSW4gdGhlIGNvbmZpZyBvZiB0aGUgYXBwIG1vZHVsZTpcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRMb2dpblVybCgnL2FjY2VzcyMvbG9naW4nKTtcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRMb2dvdXRVcmwoJy9hY2Nlc3MjL2xvZ2luJyk7XG4gKiBzb2NrZXRTZXJ2aWNlUHJvdmlkZXIuc2V0UmVjb25uZWN0aW9uTWF4VGltZUluU2VjcygxNSk7XG4gKiBUaGlzIGRlZmluZXMgaG93IG11Y2ggdGltZSB3ZSBjYW4gd2FpdCB0byBlc3RhYmxpc2ggYSBzdWNjZXNzdWwgY29ubmVjdGlvbiBiZWZvcmUgcmVqZWN0aW5nIHRoZSBjb25uZWN0aW9uIChzb2NrZXRTZXJ2aWNlLmNvbm5lY3RJTykgd2l0aCBhIHRpbWVvdXQuIGJ5IGRlZmF1bHQsIGl0IHdpbGwgdHJ5IGZvciAxNSBzZWNvbmRzIHRvIGdldCBhIGNvbm5lY3Rpb24gYW5kIHRoZW4gZ2l2ZSB1cFxuICogIFxuICogQmVmb3JlIGFueSBzb2NrZXQgdXNlIGluIHlvdXIgc2VydmljZXMgb3IgcmVzb2x2ZSBibG9ja3MsIGNvbm5lY3QoKSBtYWtlcyBzdXJlIHRoYXQgd2UgaGF2ZSBhbiBlc3RhYmxpc2hlZCBhdXRoZW50aWNhdGVkIGNvbm5lY3Rpb24gYnkgdXNpbmcgdGhlIGZvbGxvd2luZzpcbiAqIHNvY2tldFNlcnZpY2UuY29ubmVjdCgpLnRoZW4oXG4gKiBmdW5jdGlvbihzb2NrZXQpeyAuLi4gc29ja2V0LmVtaXQoKS4uIH0pLmNhdGNoKGZ1bmN0aW9uKGVycikgey4uLn0pXG4gKiBcbiAqIFxuICovXG5hbmd1bGFyXG4gICAgLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcpXG4gICAgLy8gY29udmVuaWVudCBzZXJ2aWNlIHJldHVybmluZyBzZXNzaW9uVXNlclxuICAgIC5mYWN0b3J5KCdzZXNzaW9uVXNlcicsIGZ1bmN0aW9uICgkYXV0aCkge1xuICAgICAgICByZXR1cm4gJGF1dGguZ2V0U2Vzc2lvblVzZXIoKTtcbiAgICB9KVxuICAgIC5wcm92aWRlcignJGF1dGgnLCBhdXRoUHJvdmlkZXIpO1xuXG5mdW5jdGlvbiBhdXRoUHJvdmlkZXIoKSB7XG5cbiAgICB2YXIgbG9naW5VcmwsIGxvZ291dFVybCwgZGVidWcsIHJlY29ubmVjdGlvbk1heFRpbWUgPSAxNTtcblxuICAgIHRoaXMuc2V0RGVidWcgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgZGVidWcgPSB2YWx1ZTtcbiAgICB9O1xuXG4gICAgdGhpcy5zZXRMb2dpblVybCA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICBsb2dpblVybCA9IHZhbHVlO1xuICAgIH07XG5cbiAgICB0aGlzLnNldExvZ291dFVybCA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICBsb2dvdXRVcmwgPSB2YWx1ZTtcbiAgICB9O1xuXG4gICAgdGhpcy5zZXRSZWNvbm5lY3Rpb25NYXhUaW1lSW5TZWNzID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgIHJlY29ubmVjdGlvbk1heFRpbWUgPSB2YWx1ZSAqIDEwMDA7XG4gICAgfTtcblxuICAgIHRoaXMuJGdldCA9IGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkbG9jYXRpb24sICR0aW1lb3V0LCAkcSwgJHdpbmRvdykge1xuXG4gICAgICAgIHZhciBzb2NrZXQ7XG4gICAgICAgIHZhciB1c2VyVG9rZW4gPSByZXRyaWV2ZVRva2VuKCk7XG4gICAgICAgIHZhciBzZXNzaW9uVXNlciA9IHsgY29ubmVjdGVkOiBmYWxzZSB9O1xuXG4gICAgICAgIGlmICghdXNlclRva2VuKSB7XG4gICAgICAgICAgICAvLyBAVE9ETzogdGhpcyByaWdodCB3YXkgdG8gcmVkaXJlY3QgaWYgd2UgaGF2ZSBubyB0b2tlbiB3aGVuIHdlIHJlZnJlc2ggb3IgaGl0IHRoZSBhcHAuXG4gICAgICAgICAgICAvLyAgcmVkaXJlY3QobG9naW5VcmwpO1xuICAgICAgICAgICAgLy8gYnV0IGl0IHdvdWxkIHByZXZlbnQgbW9zdCB1bml0IHRlc3RzIGZyb20gcnVubmluZyBiZWNhdXNlIHRoaXMgbW9kdWxlIGlzIHRpZ2hseSBjb3VwbGVkIHdpdGggYWxsIHVuaXQgdGVzdHMgKGRlcGVuZHMgb24gaXQpYXQgdGhpcyB0aW1lIDpcblxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnRva2VuID0gdXNlclRva2VuO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBjb25uZWN0OiBjb25uZWN0LFxuICAgICAgICAgICAgbG9nb3V0OiBsb2dvdXQsXG4gICAgICAgICAgICBnZXRTZXNzaW9uVXNlcjogZ2V0U2Vzc2lvblVzZXJcbiAgICAgICAgfTtcblxuXG4gICAgICAgIC8vLy8vLy8vLy8vLy8vLy8vLy9cblxuICAgICAgICBmdW5jdGlvbiBnZXRTZXNzaW9uVXNlcigpIHtcbiAgICAgICAgICAgIC8vIHRoZSBvYmplY3Qgd2lsbCBoYXZlIHRoZSB1c2VyIGluZm9ybWF0aW9uIHdoZW4gdGhlIGNvbm5lY3Rpb24gaXMgZXN0YWJsaXNoZWQuIE90aGVyd2lzZSBpdHMgY29ubmVjdGlvbiBwcm9wZXJ0eSB3aWxsIGJlIGZhbHNlOyBcbiAgICAgICAgICAgIHJldHVybiBzZXNzaW9uVXNlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiByZXR1cm5zIGEgcHJvbWlzZSBcbiAgICAgICAgICogdGhlIHN1Y2Nlc3MgZnVuY3Rpb24gcmVjZWl2ZXMgdGhlIHNvY2tldCBhcyBhIHBhcmFtZXRlclxuICAgICAgICAgKi9cbiAgICAgICAgZnVuY3Rpb24gY29ubmVjdCgpIHtcbiAgICAgICAgICAgIGlmICghc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc2V0dXAoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBnZXRGb3JWYWxpZENvbm5lY3Rpb24oKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgICAgICAgIC8vIGNvbm5lY3Rpb24gY291bGQgYmUgbG9zdCBkdXJpbmcgbG9nb3V0Li5zbyBpdCBjb3VsZCBtZWFuIHdlIGhhdmUgbm90IGxvZ291dCBvbiBzZXJ2ZXIgc2lkZS5cbiAgICAgICAgICAgIGlmIChzb2NrZXQpIHtcbiAgICAgICAgICAgICAgICBzb2NrZXQuZW1pdCgnbG9nb3V0JywgdXNlclRva2VuKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIGdldEZvclZhbGlkQ29ubmVjdGlvbigpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG4gICAgICAgICAgICBpZiAoc2Vzc2lvblVzZXIuY29ubmVjdGVkKSB7XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAvLyBiZWluZyB0aGUgc2NlbmUsIHNvY2tldC5pbyBpcyB0cnlpbmcgdG8gcmVjb25uZWN0IGFuZCBhdXRoZW50aWNhdGUgaWYgdGhlIGNvbm5lY3Rpb24gd2FzIGxvc3Q7XG4gICAgICAgICAgICAgICAgcmVjb25uZWN0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgICAgICB9KS5jYXRjaChmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlamVjdCgnVVNFUl9OT1RfQ09OTkVDVEVEJyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHJlY29ubmVjdCgpIHtcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG5cbiAgICAgICAgICAgIGlmIChzZXNzaW9uVXNlci5jb25uZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHNvY2tldCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvL0BUT0RPIFRPIFRISU5LIEFCT1VUOiwgaWYgdGhlIHNvY2tldCBpcyBjb25uZWN0aW5nIGFscmVhZHksIG1lYW5zIHRoYXQgYSBjb25uZWN0IHdhcyBjYWxsZWQgYWxyZWFkeSBieSBhbm90aGVyIGFzeW5jIGNhbGwsIHNvIGp1c3Qgd2FpdCBmb3IgdXNlcl9jb25uZWN0ZWRcblxuXG5cbiAgICAgICAgICAgIC8vIGlmIHRoZSByZXNwb25zZSBkb2VzIG5vdCBjb21lIHF1aWNrLi5sZXQncyBnaXZlIHVwIHNvIHdlIGRvbid0IGdldCBzdHVjayB3YWl0aW5nXG4gICAgICAgICAgICAvLyBAVE9ETzpvdGhlciB3YXkgaXMgdG8gd2F0Y2ggZm9yIGEgY29ubmVjdGlvbiBlcnJvci4uLlxuICAgICAgICAgICAgdmFyIGFjY2VwdGFibGVEZWxheTtcbiAgICAgICAgICAgIHZhciBvZmYgPSAkcm9vdFNjb3BlLiRvbigndXNlcl9jb25uZWN0ZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgb2ZmKCk7XG4gICAgICAgICAgICAgICAgaWYgKGFjY2VwdGFibGVEZWxheSkge1xuICAgICAgICAgICAgICAgICAgICAkdGltZW91dC5jYW5jZWwoYWNjZXB0YWJsZURlbGF5KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIGFjY2VwdGFibGVEZWxheSA9ICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBvZmYoKTtcbiAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoJ1RJTUVPVVQnKTtcbiAgICAgICAgICAgIH0sIHJlY29ubmVjdGlvbk1heFRpbWUpO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHNldHVwKCkge1xuICAgICAgICAgICAgaWYgKHNvY2tldCkge1xuICAgICAgICAgICAgICAgIC8vYWxyZWFkeSBjYWxsZWQuLi5cbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB2YXIgdG9rZW5WYWxpZGl0eVRpbWVvdXQ7XG4gICAgICAgICAgICAvLyBlc3RhYmxpc2ggY29ubmVjdGlvbiB3aXRob3V0IHBhc3NpbmcgdGhlIHRva2VuIChzbyB0aGF0IGl0IGlzIG5vdCB2aXNpYmxlIGluIHRoZSBsb2cpXG4gICAgICAgICAgICBzb2NrZXQgPSBpby5jb25uZWN0KHtcbiAgICAgICAgICAgICAgICAnZm9yY2VOZXcnOiB0cnVlLFxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNvY2tldFxuICAgICAgICAgICAgICAgIC5vbignY29ubmVjdCcsIG9uQ29ubmVjdClcbiAgICAgICAgICAgICAgICAub24oJ2F1dGhlbnRpY2F0ZWQnLCBvbkF1dGhlbnRpY2F0ZWQpXG4gICAgICAgICAgICAgICAgLm9uKCd1bmF1dGhvcml6ZWQnLCBvblVuYXV0aG9yaXplZClcbiAgICAgICAgICAgICAgICAub24oJ2xvZ2dlZF9vdXQnLCBvbkxvZ091dClcbiAgICAgICAgICAgICAgICAub24oJ2Rpc2Nvbm5lY3QnLCBvbkRpc2Nvbm5lY3QpO1xuXG4gICAgICAgICAgICAvLyBUT0RPOiB0aGlzIGZvbGxvd293aW5nIGV2ZW50IGlzIHN0aWxsIHVzZWQuPz8/Li4uLlxuICAgICAgICAgICAgc29ja2V0XG4gICAgICAgICAgICAgICAgLm9uKCdjb25uZWN0X2Vycm9yJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3QoKSB7XG4gICAgICAgICAgICAgICAgLy8gdGhlIHNvY2tldCBpcyBjb25uZWN0ZWQsIHRpbWUgdG8gcGFzcyB0aGUgdG9rZW4gdG8gYXV0aGVudGljYXRlIGFzYXBcbiAgICAgICAgICAgICAgICAvLyBiZWNhdXNlIHRoZSB0b2tlbiBpcyBhYm91dCB0byBleHBpcmUuLi5pZiBpdCBleHBpcmVzIHdlIHdpbGwgaGF2ZSB0byByZWxvZyBpblxuICAgICAgICAgICAgICAgIHNldENvbm5lY3Rpb25TdGF0dXMoZmFsc2UpO1xuICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KCdhdXRoZW50aWNhdGUnLCB7IHRva2VuOiB1c2VyVG9rZW4gfSk7IC8vIHNlbmQgdGhlIGp3dFxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkRpc2Nvbm5lY3QoKSB7XG4gICAgICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ1Nlc3Npb24gZGlzY29ubmVjdGVkJyk7IH1cbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoJ3VzZXJfZGlzY29ubmVjdGVkJyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uQXV0aGVudGljYXRlZChyZWZyZXNoVG9rZW4pIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIC8vIHRoZSBzZXJ2ZXIgY29uZmlybWVkIHRoYXQgdGhlIHRva2VuIGlzIHZhbGlkLi4ud2UgYXJlIGdvb2QgdG8gZ29cbiAgICAgICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnYXV0aGVudGljYXRlZCwgcmVjZWl2ZWQgbmV3IHRva2VuOiAnICsgKHJlZnJlc2hUb2tlbiAhPSB1c2VyVG9rZW4pKTsgfVxuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS50b2tlbiA9IHJlZnJlc2hUb2tlbjtcbiAgICAgICAgICAgICAgICB1c2VyVG9rZW4gPSByZWZyZXNoVG9rZW47XG4gICAgICAgICAgICAgICAgc2V0TG9naW5Vc2VyKHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyh0cnVlKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0TmV3VG9rZW5CZWZvcmVFeHBpcmF0aW9uKHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KCd1c2VyX2Nvbm5lY3RlZCcsc2Vzc2lvblVzZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkxvZ091dCgpIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIC8vIHRva2VuIGlzIG5vIGxvbmdlciBhdmFpbGFibGUuXG4gICAgICAgICAgICAgICAgZGVsZXRlIGxvY2FsU3RvcmFnZS50b2tlbjtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICByZWRpcmVjdChsb2dvdXRVcmwgfHwgbG9naW5VcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvblVuYXV0aG9yaXplZChtc2cpIHtcbiAgICAgICAgICAgICAgICBjbGVhclRva2VuVGltZW91dCgpO1xuICAgICAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCd1bmF1dGhvcml6ZWQ6ICcgKyBKU09OLnN0cmluZ2lmeShtc2cuZGF0YSkpOyB9XG4gICAgICAgICAgICAgICAgc2V0Q29ubmVjdGlvblN0YXR1cyhmYWxzZSk7XG4gICAgICAgICAgICAgICAgcmVkaXJlY3QobG9naW5VcmwpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBzZXRDb25uZWN0aW9uU3RhdHVzKGNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmNvbm5lY3RlZCA9IGNvbm5lY3RlZDtcbiAgICAgICAgICAgICAgICAvL2NvbnNvbGUuZGVidWcoXCJDb25uZWN0aW9uIHN0YXR1czpcIiArIEpTT04uc3RyaW5naWZ5KHNlc3Npb25Vc2VyKSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHNldExvZ2luVXNlcih0b2tlbikge1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkID0gZGVjb2RlKHRva2VuKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gXy5hc3NpZ24oc2Vzc2lvblVzZXIscGF5bG9hZCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIGNsZWFyVG9rZW5UaW1lb3V0KCkge1xuICAgICAgICAgICAgICAgIGlmICh0b2tlblZhbGlkaXR5VGltZW91dCkge1xuICAgICAgICAgICAgICAgICAgICAkdGltZW91dC5jYW5jZWwodG9rZW5WYWxpZGl0eVRpbWVvdXQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gZGVjb2RlKHRva2VuKSB7XG4gICAgICAgICAgICAgICAgdmFyIGJhc2U2NFVybCA9IHRva2VuLnNwbGl0KCcuJylbMV07XG4gICAgICAgICAgICAgICAgdmFyIGJhc2U2NCA9IGJhc2U2NFVybC5yZXBsYWNlKCctJywgJysnKS5yZXBsYWNlKCdfJywgJy8nKTtcbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZCA9IEpTT04ucGFyc2UoJHdpbmRvdy5hdG9iKGJhc2U2NCkpO1xuICAgICAgICAgICAgICAgIHJldHVybiBwYXlsb2FkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiByZXF1ZXN0TmV3VG9rZW5CZWZvcmVFeHBpcmF0aW9uKHRva2VuKSB7XG4gICAgICAgICAgICAgICAgLy8gcmVxdWVzdCBhIGxpdHRsZSBiZWZvcmUuLi5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZCA9IGRlY29kZSh0b2tlbiwgeyBjb21wbGV0ZTogZmFsc2UgfSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgaW5pdGlhbCA9IHBheWxvYWQuZHVyO1xuXG4gICAgICAgICAgICAgICAgdmFyIGR1cmF0aW9uID0gKGluaXRpYWwgKiA5MCAvIDEwMCkgfCAwO1xuICAgICAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdTY2hlZHVsZSB0byByZXF1ZXN0IGEgbmV3IHRva2VuIGluICcgKyBkdXJhdGlvbiArICcgc2Vjb25kcyAodG9rZW4gZHVyYXRpb246JyArIGluaXRpYWwgKyAnKScpOyB9XG4gICAgICAgICAgICAgICAgdG9rZW5WYWxpZGl0eVRpbWVvdXQgPSAkdGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdUaW1lIHRvIHJlcXVlc3QgbmV3IHRva2VuICcgKyBpbml0aWFsKTsgfVxuICAgICAgICAgICAgICAgICAgICBzb2NrZXQuZW1pdCgnYXV0aGVudGljYXRlJywgeyB0b2tlbjogdG9rZW4gfSk7XG4gICAgICAgICAgICAgICAgICAgIC8vIE5vdGU6IElmIGNvbW11bmljYXRpb24gY3Jhc2hlcyByaWdodCBhZnRlciB3ZSBlbWl0dGVkIGFuZCB3aGVuIHNlcnZlcnMgaXMgc2VuZGluZyBiYWNrIHRoZSB0b2tlbixcbiAgICAgICAgICAgICAgICAgICAgLy8gd2hlbiB0aGUgY2xpZW50IHJlZXN0YWJsaXNoZXMgdGhlIGNvbm5lY3Rpb24sIHdlIHdvdWxkIGhhdmUgdG8gbG9naW4gYmVjYXVzZSB0aGUgcHJldmlvdXMgdG9rZW4gd291bGQgYmUgaW52YWxpZGF0ZWQuXG4gICAgICAgICAgICAgICAgfSwgZHVyYXRpb24gKiAxMDAwKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHJldHJpZXZlVG9rZW4oKSB7XG4gICAgICAgICAgICB2YXIgdXNlclRva2VuID0gJGxvY2F0aW9uLnNlYXJjaCgpLnRva2VuO1xuICAgICAgICAgICAgaWYgKHVzZXJUb2tlbikge1xuICAgICAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdVc2luZyB0b2tlbiBwYXNzZWQgZHVyaW5nIHJlZGlyZWN0aW9uOiAnICsgdXNlclRva2VuKTsgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICB1c2VyVG9rZW4gPSBsb2NhbFN0b3JhZ2UudG9rZW47XG4gICAgICAgICAgICAgICAgaWYgKHVzZXJUb2tlbikge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnVXNpbmcgVG9rZW4gaW4gbG9jYWwgc3RvcmFnZTogJyArIHVzZXJUb2tlbik7IH1cbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHVzZXJUb2tlbjtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHJlZGlyZWN0KHVybCkge1xuICAgICAgICAgICAgd2luZG93LmxvY2F0aW9uLnJlcGxhY2UodXJsIHx8ICdiYWRVcmwuaHRtbCcpO1xuICAgICAgICB9XG4gICAgfTtcbn1cbn0oKSk7XG5cbihmdW5jdGlvbigpIHtcblwidXNlIHN0cmljdFwiO1xuXG4vKiogXG4gKiBUaGlzIHNlcnZpY2UgYWxsb3dzIHlvdXIgYXBwbGljYXRpb24gY29udGFjdCB0aGUgd2Vic29ja2V0IGFwaS5cbiAqIFxuICogSXQgd2lsbCBlbnN1cmUgdGhhdCB0aGUgY29ubmVjdGlvbiBpcyBhdmFpbGFibGUgYW5kIHVzZXIgaXMgYXV0aGVudGljYXRlZCBiZWZvcmUgZmV0Y2hpbmcgZGF0YS5cbiAqIFxuICovXG5hbmd1bGFyXG4gICAgLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcpXG4gICAgLnByb3ZpZGVyKCckc29ja2V0aW8nLCBzb2NrZXRpb1Byb3ZpZGVyKTtcblxuZnVuY3Rpb24gc29ja2V0aW9Qcm92aWRlcigpIHtcbiAgICB2YXIgZGVidWc7XG4gICAgdGhpcy5zZXREZWJ1ZyA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICBkZWJ1ZyA9IHZhbHVlO1xuICAgIH07XG5cbiAgICB0aGlzLiRnZXQgPSBmdW5jdGlvbiBzb2NrZXRpb1NlcnZpY2UoJHJvb3RTY29wZSwgJHEsICRhdXRoKSB7XG5cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIG9uOiBvbixcbiAgICAgICAgICAgIGVtaXQ6IGVtaXQsXG4gICAgICAgICAgICBsb2dvdXQ6ICRhdXRoLmxvZ291dCxcbiAgICAgICAgICAgIGZldGNoOiBmZXRjaCxcbiAgICAgICAgICAgIHBvc3Q6IHBvc3QsXG4gICAgICAgICAgICBub3RpZnk6IG5vdGlmeVxuICAgICAgICB9O1xuXG4gICAgICAgIC8vLy8vLy8vLy8vLy8vLy8vLy9cbiAgICAgICAgZnVuY3Rpb24gb24oZXZlbnROYW1lLCBjYWxsYmFjaykge1xuICAgICAgICAgICAgJGF1dGguY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKHNvY2tldCkge1xuICAgICAgICAgICAgICAgIHNvY2tldC5vbihldmVudE5hbWUsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGFyZ3MgPSBhcmd1bWVudHM7XG4gICAgICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGFwcGx5KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrLmFwcGx5KHNvY2tldCwgYXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gZGVwcmVjYXRlZCwgdXNlIHBvc3Qvbm90aWZ5XG4gICAgICAgIGZ1bmN0aW9uIGVtaXQoZXZlbnROYW1lLCBkYXRhLCBjYWxsYmFjaykge1xuICAgICAgICAgICAgJGF1dGguY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKHNvY2tldCkge1xuICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KGV2ZW50TmFtZSwgZGF0YSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgYXJncyA9IGFyZ3VtZW50cztcbiAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYXBwbHkoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGNhbGxiYWNrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2suYXBwbHkoc29ja2V0LCBhcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBmZXRjaCBkYXRhIHRoZSB3YXkgd2UgY2FsbCBhbiBhcGkgXG4gICAgICAgICAqIGh0dHA6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvMjA2ODUyMDgvd2Vic29ja2V0LXRyYW5zcG9ydC1yZWxpYWJpbGl0eS1zb2NrZXQtaW8tZGF0YS1sb3NzLWR1cmluZy1yZWNvbm5lY3Rpb25cbiAgICAgICAgICogXG4gICAgICAgICAqL1xuICAgICAgICBmdW5jdGlvbiBmZXRjaChvcGVyYXRpb24sIGRhdGEpIHtcbiAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdGZXRjaGluZyAnICsgb3BlcmF0aW9uICsgJy4uLicpOyB9XG4gICAgICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpXG4gICAgICAgIH1cblxuICAgICAgICAvKipcbiAgICAgICAgICogbm90aWZ5IGlzIHNpbWlsYXIgdG8gZmV0Y2ggYnV0IG1vcmUgbWVhbmluZ2Z1bFxuICAgICAgICAgKi9cbiAgICAgICAgZnVuY3Rpb24gbm90aWZ5KG9wZXJhdGlvbiwgZGF0YSkge1xuICAgICAgICAgICAgaWYgKGRlYnVnKSB7IGNvbnNvbGUuZGVidWcoJ05vdGlmeWluZyAnICsgb3BlcmF0aW9uICsgJy4uLicpOyB9XG4gICAgICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpXG4gICAgICAgIH1cblxuICAgICAgICAvKipcbiAgICAgICAgICogcG9zdCBzZW5kcyBkYXRhIHRvIHRoZSBzZXJ2ZXIuXG4gICAgICAgICAqIGlmIGRhdGEgd2FzIGFscmVhZHkgc3VibWl0dGVkLCBpdCB3b3VsZCBqdXN0IHJldHVybiAtIHdoaWNoIGNvdWxkIGhhcHBlbiB3aGVuIGhhbmRsaW5nIGRpc2Nvbm5lY3Rpb24uXG4gICAgICAgICAqIFxuICAgICAgICAgKi9cbiAgICAgICAgZnVuY3Rpb24gcG9zdChvcGVyYXRpb24sIGRhdGEpIHtcbiAgICAgICAgICAgIGlmIChkZWJ1ZykgeyBjb25zb2xlLmRlYnVnKCdQb3N0aW5nICcgKyBvcGVyYXRpb24gKyAnLi4uJyk7IH1cbiAgICAgICAgICAgIHJldHVybiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSk7XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSkge1xuXG4gICAgICAgICAgICByZXR1cm4gJGF1dGguY29ubmVjdCgpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25Db25uZWN0aW9uU3VjY2Vzcywgb25Db25uZWN0aW9uRXJyb3IpXG4gICAgICAgICAgICAgICAgOy8vIC5jYXRjaChvbkNvbm5lY3Rpb25FcnJvcik7XG5cbiAgICAgICAgICAgIC8vLy8vLy8vLy8vL1xuICAgICAgICAgICAgZnVuY3Rpb24gb25Db25uZWN0aW9uU3VjY2Vzcyhzb2NrZXQpIHtcbiAgICAgICAgICAgICAgICAvLyBidXQgd2hhdCBpZiB3ZSBoYXZlIG5vdCBjb25uZWN0aW9uIGJlZm9yZSB0aGUgZW1pdCwgaXQgd2lsbCBxdWV1ZSBjYWxsLi4ubm90IHNvIGdvb2QuICAgICAgICBcbiAgICAgICAgICAgICAgICB2YXIgZGVmZXJyZWQgPSAkcS5kZWZlcigpO1xuICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KCdhcGknLCBvcGVyYXRpb24sIGRhdGEsIGZ1bmN0aW9uIChyZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHJlc3VsdC5jb2RlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoZGVidWcpIHsgY29uc29sZS5kZWJ1ZygnRXJyb3Igb24gJyArIG9wZXJhdGlvbiArICcgLT4nICsgSlNPTi5zdHJpbmdpZnkocmVzdWx0KSk7IH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlamVjdCh7IGNvZGU6IHJlc3VsdC5jb2RlLCBkZXNjcmlwdGlvbjogcmVzdWx0LmRhdGEgfSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHJlc3VsdC5kYXRhKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3Rpb25FcnJvcihlcnIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJHEucmVqZWN0KHsgY29kZTogJ0NPTk5FQ1RJT05fRVJSJywgZGVzY3JpcHRpb246IGVyciB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbn0oKSk7XG4iXX0=
