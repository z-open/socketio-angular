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
 * This defines how much time we can wait to establish a successul connection before rejecting the connection (socketService.connectIO) with a timeout
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

    var loginUrl, logoutUrl, reconnectionMaxTime;

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
            socket.emit('logout', userToken);
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
            }, reconnectionMaxTime | 1000 * 60);

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

            // TODO: this followowing event is still used.....
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
                localStorage.token = null;
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
socketService.$inject = ["$rootScope", "$q", "$auth"];
angular
    .module('socketio-auth')
    .service('$socketio', socketService);

function socketService($rootScope, $q, $auth) {

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
     * post will handle later on, duplicate record by providing a stamp.
     */
    function post(operation, data) {
        console.debug('Posting ' + operation + '...');
        return socketEmit(operation, data)
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


//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFuZ3VsYXItc29ja2V0aW8uanMiLCIvc291cmNlL3NvY2tldC5tb2R1bGUuanMiLCIvc291cmNlL3NlcnZpY2VzL2F1dGguc2VydmljZS5qcyIsIi9zb3VyY2Uvc2VydmljZXMvc29ja2V0LnNlcnZpY2UuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsQ0FBQyxXQUFXO0FBQ1o7O0FDREEsUUFBQSxPQUFBLGlCQUFBOzs7QURNQSxDQUFDLFdBQVc7QUFDWjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FFYUE7S0FDQSxPQUFBO0tBQ0EsU0FBQSxTQUFBOztBQUVBLFNBQUEsZUFBQTs7SUFFQSxJQUFBLFVBQUEsV0FBQTs7SUFFQSxLQUFBLGNBQUEsVUFBQSxPQUFBO1FBQ0EsV0FBQTs7O0lBR0EsS0FBQSxlQUFBLFVBQUEsT0FBQTtRQUNBLFlBQUE7OztJQUdBLEtBQUEsK0JBQUEsVUFBQSxPQUFBO1FBQ0Esc0JBQUEsUUFBQTs7O0lBR0EsS0FBQSxnRUFBQSxVQUFBLFlBQUEsV0FBQSxVQUFBLElBQUEsU0FBQTs7UUFFQSxJQUFBO1FBQ0EsSUFBQSxZQUFBO1FBQ0EsSUFBQSxjQUFBO1FBQ0EsV0FBQSxjQUFBOztRQUVBLElBQUEsQ0FBQSxXQUFBOzs7OztlQUtBO1lBQ0EsYUFBQSxRQUFBOztRQUVBLE9BQUE7WUFDQSxTQUFBO1lBQ0EsUUFBQTs7Ozs7Ozs7UUFRQSxTQUFBLFVBQUE7WUFDQSxJQUFBLENBQUEsUUFBQTtnQkFDQTs7WUFFQSxPQUFBOzs7UUFHQSxTQUFBLFNBQUE7O1lBRUEsT0FBQSxLQUFBLFVBQUE7OztRQUdBLFNBQUEsd0JBQUE7WUFDQSxJQUFBLFdBQUEsR0FBQTtZQUNBLElBQUEsWUFBQSxXQUFBO2dCQUNBLFNBQUEsUUFBQTttQkFDQTs7Z0JBRUEsWUFBQSxLQUFBLFlBQUE7b0JBQ0EsU0FBQSxRQUFBO21CQUNBLE1BQUEsVUFBQSxLQUFBO29CQUNBLFNBQUEsT0FBQTs7O1lBR0EsT0FBQSxTQUFBOzs7UUFHQSxTQUFBLFlBQUE7WUFDQSxJQUFBLFdBQUEsR0FBQTs7WUFFQSxJQUFBLFlBQUEsV0FBQTtnQkFDQSxTQUFBLFFBQUE7Ozs7WUFJQSxJQUFBO1lBQ0EsSUFBQSxNQUFBLFdBQUEsSUFBQSxrQkFBQSxZQUFBO2dCQUNBO2dCQUNBLElBQUEsaUJBQUE7b0JBQ0EsU0FBQSxPQUFBOztnQkFFQSxTQUFBLFFBQUE7OztZQUdBLGtCQUFBLFNBQUEsWUFBQTtnQkFDQTtnQkFDQSxTQUFBLE9BQUE7ZUFDQSxzQkFBQSxPQUFBOztZQUVBLE9BQUEsU0FBQTs7O1FBR0EsU0FBQSxRQUFBO1lBQ0EsSUFBQSxRQUFBOztnQkFFQTs7WUFFQSxJQUFBOztZQUVBLFNBQUEsR0FBQSxRQUFBO2dCQUNBLFlBQUE7OztZQUdBO2lCQUNBLEdBQUEsV0FBQTtpQkFDQSxHQUFBLGlCQUFBO2lCQUNBLEdBQUEsZ0JBQUE7aUJBQ0EsR0FBQSxjQUFBO2lCQUNBLEdBQUEsY0FBQTs7O1lBR0E7aUJBQ0EsR0FBQSxpQkFBQSxZQUFBO29CQUNBLG9CQUFBOzs7O1lBSUEsU0FBQSxZQUFBOzs7Z0JBR0Esb0JBQUE7Z0JBQ0EsT0FBQSxLQUFBLGdCQUFBLEVBQUEsT0FBQTs7O1lBR0EsU0FBQSxlQUFBO2dCQUNBLFFBQUEsTUFBQTtnQkFDQSxvQkFBQTs7O1lBR0EsU0FBQSxnQkFBQSxjQUFBO2dCQUNBOztnQkFFQSxRQUFBLE1BQUEseUNBQUEsZ0JBQUE7Z0JBQ0EsYUFBQSxRQUFBO2dCQUNBLFlBQUE7Z0JBQ0EsYUFBQTtnQkFDQSxvQkFBQTtnQkFDQSxnQ0FBQTtnQkFDQSxXQUFBLFdBQUE7OztZQUdBLFNBQUEsV0FBQTtnQkFDQTs7Z0JBRUEsYUFBQSxRQUFBO2dCQUNBLG9CQUFBO2dCQUNBLFNBQUEsYUFBQTs7O1lBR0EsU0FBQSxlQUFBLEtBQUE7Z0JBQ0E7Z0JBQ0EsUUFBQSxNQUFBLG1CQUFBLEtBQUEsVUFBQSxJQUFBO2dCQUNBLG9CQUFBO2dCQUNBLFNBQUE7OztZQUdBLFNBQUEsb0JBQUEsV0FBQTtnQkFDQSxZQUFBLFlBQUE7Ozs7WUFJQSxTQUFBLGFBQUEsT0FBQTtnQkFDQSxJQUFBLFVBQUEsT0FBQTtnQkFDQSxZQUFBLEtBQUEsUUFBQTtnQkFDQSxZQUFBLFVBQUEsUUFBQTtnQkFDQSxZQUFBLFlBQUEsUUFBQTtnQkFDQSxZQUFBLFdBQUEsUUFBQTtnQkFDQSxZQUFBLE9BQUEsUUFBQTs7O1lBR0EsU0FBQSxvQkFBQTtnQkFDQSxJQUFBLHNCQUFBO29CQUNBLFNBQUEsT0FBQTs7OztZQUlBLFNBQUEsT0FBQSxPQUFBO2dCQUNBLElBQUEsWUFBQSxNQUFBLE1BQUEsS0FBQTtnQkFDQSxJQUFBLFNBQUEsVUFBQSxRQUFBLEtBQUEsS0FBQSxRQUFBLEtBQUE7Z0JBQ0EsSUFBQSxVQUFBLEtBQUEsTUFBQSxRQUFBLEtBQUE7Z0JBQ0EsT0FBQTs7O1lBR0EsU0FBQSxnQ0FBQSxPQUFBOztnQkFFQSxJQUFBLFVBQUEsT0FBQSxPQUFBLEVBQUEsVUFBQTs7Z0JBRUEsSUFBQSxVQUFBLFFBQUE7O2dCQUVBLElBQUEsV0FBQSxDQUFBLFVBQUEsS0FBQSxPQUFBO2dCQUNBLFFBQUEsTUFBQSx3Q0FBQSxXQUFBLDhCQUFBLFVBQUE7Z0JBQ0EsdUJBQUEsU0FBQSxZQUFBO29CQUNBLFFBQUEsTUFBQSwrQkFBQTtvQkFDQSxPQUFBLEtBQUEsZ0JBQUEsRUFBQSxPQUFBOzs7bUJBR0EsV0FBQTs7OztRQUlBLFNBQUEsZ0JBQUE7WUFDQSxJQUFBLFlBQUEsVUFBQSxTQUFBO1lBQ0EsSUFBQSxXQUFBO2dCQUNBLFFBQUEsTUFBQSw0Q0FBQTttQkFDQTtnQkFDQSxZQUFBLGFBQUE7Z0JBQ0EsSUFBQSxXQUFBO29CQUNBLFFBQUEsTUFBQSxtQ0FBQTt1QkFDQTs7OztZQUlBLE9BQUE7OztRQUdBLFNBQUEsU0FBQSxLQUFBO1lBQ0EsT0FBQSxTQUFBLFFBQUEsT0FBQTs7Ozs7O0FGY0EsQ0FBQyxXQUFXO0FBQ1o7Ozs7Ozs7OztBR3pQQTtLQUNBLE9BQUE7S0FDQSxRQUFBLGFBQUE7O0FBRUEsU0FBQSxjQUFBLFlBQUEsSUFBQSxPQUFBOztJQUVBLEtBQUEsS0FBQTtJQUNBLEtBQUEsT0FBQTtJQUNBLEtBQUEsU0FBQSxNQUFBO0lBQ0EsS0FBQSxRQUFBO0lBQ0EsS0FBQSxPQUFBO0lBQ0EsS0FBQSxTQUFBOzs7SUFHQSxTQUFBLEdBQUEsV0FBQSxVQUFBO1FBQ0EsTUFBQSxVQUFBLEtBQUEsVUFBQSxRQUFBO1lBQ0EsT0FBQSxHQUFBLFdBQUEsWUFBQTtnQkFDQSxJQUFBLE9BQUE7Z0JBQ0EsV0FBQSxPQUFBLFlBQUE7b0JBQ0EsU0FBQSxNQUFBLFFBQUE7Ozs7OztJQU1BLFNBQUEsS0FBQSxXQUFBLE1BQUEsVUFBQTtRQUNBLE1BQUEsVUFBQSxLQUFBLFVBQUEsUUFBQTtZQUNBLE9BQUEsS0FBQSxXQUFBLE1BQUEsWUFBQTtnQkFDQSxJQUFBLE9BQUE7Z0JBQ0EsV0FBQSxPQUFBLFlBQUE7b0JBQ0EsSUFBQSxVQUFBO3dCQUNBLFNBQUEsTUFBQSxRQUFBOzs7Ozs7Ozs7Ozs7SUFZQSxTQUFBLE1BQUEsV0FBQSxNQUFBO1FBQ0EsUUFBQSxNQUFBLGNBQUEsWUFBQTtRQUNBLE9BQUEsV0FBQSxXQUFBOzs7Ozs7SUFNQSxTQUFBLE9BQUEsV0FBQSxNQUFBO1FBQ0EsUUFBQSxNQUFBLGVBQUEsWUFBQTtRQUNBLE9BQUEsV0FBQSxXQUFBOzs7Ozs7SUFNQSxTQUFBLEtBQUEsV0FBQSxNQUFBO1FBQ0EsUUFBQSxNQUFBLGFBQUEsWUFBQTtRQUNBLE9BQUEsV0FBQSxXQUFBOzs7SUFHQSxTQUFBLFdBQUEsV0FBQSxNQUFBOztRQUVBLE9BQUEsTUFBQTthQUNBLEtBQUEscUJBQUE7Ozs7UUFJQSxTQUFBLG9CQUFBLFFBQUE7O1lBRUEsSUFBQSxXQUFBLEdBQUE7WUFDQSxPQUFBLEtBQUEsT0FBQSxXQUFBLE1BQUEsVUFBQSxRQUFBO2dCQUNBLElBQUEsT0FBQSxNQUFBO29CQUNBLFFBQUEsTUFBQSxjQUFBLFlBQUEsUUFBQSxLQUFBLFVBQUE7b0JBQ0EsU0FBQSxPQUFBLEVBQUEsTUFBQSxPQUFBLE1BQUEsYUFBQSxPQUFBOztxQkFFQTtvQkFDQSxTQUFBLFFBQUEsT0FBQTs7O1lBR0EsT0FBQSxTQUFBOzs7UUFHQSxTQUFBLGtCQUFBLEtBQUE7WUFDQSxPQUFBLEdBQUEsT0FBQSxFQUFBLE1BQUEsa0JBQUEsYUFBQTs7Ozs7O0FIdVFBIiwiZmlsZSI6ImFuZ3VsYXItc29ja2V0aW8uanMiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24oKSB7XG5cInVzZSBzdHJpY3RcIjtcblxuYW5ndWxhci5tb2R1bGUoJ3NvY2tldGlvLWF1dGgnLCBbXSk7XG59KCkpO1xuXG4oZnVuY3Rpb24oKSB7XG5cInVzZSBzdHJpY3RcIjtcblxuLyoqIFxuICogVGhpcyBwcm92aWRlciBoYW5kbGVzIHRoZSBoYW5kc2hha2UgdG8gYXV0aGVudGljYXRlIGEgdXNlciBhbmQgbWFpbnRhaW4gYSBzZWN1cmUgd2ViIHNvY2tldCBjb25uZWN0aW9uIHZpYSB0b2tlbnMuXG4gKiBJdCBhbHNvIHNldHMgdGhlIGxvZ2luIGFuZCBsb2dvdXQgdXJsIHBhcnRpY2lwYXRpbmcgaW4gdGhlIGF1dGhlbnRpY2F0aW9uLlxuICogXG4gKiBcbiAqIHVzYWdlIGV4YW1wbGVzOlxuICogXG4gKiBJbiB0aGUgY29uZmlnIG9mIHRoZSBhcHAgbW9kdWxlOlxuICogc29ja2V0U2VydmljZVByb3ZpZGVyLnNldExvZ2luVXJsKCcvYWNjZXNzIy9sb2dpbicpO1xuICogc29ja2V0U2VydmljZVByb3ZpZGVyLnNldExvZ291dFVybCgnL2FjY2VzcyMvbG9naW4nKTtcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRSZWNvbm5lY3Rpb25NYXhUaW1lSW5TZWNzKDE1KTtcbiAqIFRoaXMgZGVmaW5lcyBob3cgbXVjaCB0aW1lIHdlIGNhbiB3YWl0IHRvIGVzdGFibGlzaCBhIHN1Y2Nlc3N1bCBjb25uZWN0aW9uIGJlZm9yZSByZWplY3RpbmcgdGhlIGNvbm5lY3Rpb24gKHNvY2tldFNlcnZpY2UuY29ubmVjdElPKSB3aXRoIGEgdGltZW91dFxuICogIFxuICogQmVmb3JlIGFueSBzb2NrZXQgdXNlIGluIHlvdXIgc2VydmljZXMgb3IgcmVzb2x2ZSBibG9ja3MsIGNvbm5lY3QoKSBtYWtlcyBzdXJlIHRoYXQgd2UgaGF2ZSBhbiBlc3RhYmxpc2hlZCBhdXRoZW50aWNhdGVkIGNvbm5lY3Rpb24gYnkgdXNpbmcgdGhlIGZvbGxvd2luZzpcbiAqIHNvY2tldFNlcnZpY2UuY29ubmVjdCgpLnRoZW4oXG4gKiBmdW5jdGlvbihzb2NrZXQpeyAuLi4gc29ja2V0LmVtaXQoKS4uIH0pLmNhdGNoKGZ1bmN0aW9uKGVycikgey4uLn0pXG4gKiBcbiAqIFxuICovXG5hbmd1bGFyXG4gICAgLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcpXG4gICAgLnByb3ZpZGVyKCckYXV0aCcsIGF1dGhQcm92aWRlcik7XG5cbmZ1bmN0aW9uIGF1dGhQcm92aWRlcigpIHtcblxuICAgIHZhciBsb2dpblVybCwgbG9nb3V0VXJsLCByZWNvbm5lY3Rpb25NYXhUaW1lO1xuXG4gICAgdGhpcy5zZXRMb2dpblVybCA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICBsb2dpblVybCA9IHZhbHVlO1xuICAgIH07XG4gICAgXG4gICAgdGhpcy5zZXRMb2dvdXRVcmwgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgbG9nb3V0VXJsID0gdmFsdWU7XG4gICAgfTtcblxuICAgIHRoaXMuc2V0UmVjb25uZWN0aW9uTWF4VGltZUluU2VjcyA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICByZWNvbm5lY3Rpb25NYXhUaW1lID0gdmFsdWUgKiAxMDAwO1xuICAgIH07XG5cbiAgICB0aGlzLiRnZXQgPSBmdW5jdGlvbiAoJHJvb3RTY29wZSwgJGxvY2F0aW9uLCAkdGltZW91dCwgJHEsICR3aW5kb3cpIHtcblxuICAgICAgICB2YXIgc29ja2V0O1xuICAgICAgICB2YXIgdXNlclRva2VuID0gcmV0cmlldmVUb2tlbigpO1xuICAgICAgICB2YXIgc2Vzc2lvblVzZXIgPSB7fTtcbiAgICAgICAgJHJvb3RTY29wZS5zZXNzaW9uVXNlciA9IHNlc3Npb25Vc2VyO1xuXG4gICAgICAgIGlmICghdXNlclRva2VuKSB7XG4gICAgICAgICAgICAvLyBAVE9ETzogdGhpcyByaWdodCB3YXkgdG8gcmVkaXJlY3QgaWYgd2UgaGF2ZSBubyB0b2tlbiB3aGVuIHdlIHJlZnJlc2ggb3IgaGl0IHRoZSBhcHAuXG4gICAgICAgICAgICAvLyAgcmVkaXJlY3QobG9naW5VcmwpO1xuICAgICAgICAgICAgLy8gYnV0IGl0IHdvdWxkIHByZXZlbnQgbW9zdCB1bml0IHRlc3RzIGZyb20gcnVubmluZyBiZWNhdXNlIHRoaXMgbW9kdWxlIGlzIHRpZ2hseSBjb3VwbGVkIHdpdGggYWxsIHVuaXQgdGVzdHMgKGRlcGVuZHMgb24gaXQpYXQgdGhpcyB0aW1lIDpcblxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnRva2VuID0gdXNlclRva2VuO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBjb25uZWN0OiBjb25uZWN0LFxuICAgICAgICAgICAgbG9nb3V0OiBsb2dvdXRcbiAgICAgICAgfTtcblxuICAgICAgICAvLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgICAgIC8qKlxuICAgICAgICAgKiByZXR1cm5zIGEgcHJvbWlzZSBcbiAgICAgICAgICogdGhlIHN1Y2Nlc3MgZnVuY3Rpb24gcmVjZWl2ZXMgdGhlIHNvY2tldCBhcyBhIHBhcmFtZXRlclxuICAgICAgICAgKi9cbiAgICAgICAgZnVuY3Rpb24gY29ubmVjdCgpIHtcbiAgICAgICAgICAgIGlmICghc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc2V0dXAoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBnZXRGb3JWYWxpZENvbm5lY3Rpb24oKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgICAgICAgIC8vIGNvbm5lY3Rpb24gY291bGQgYmUgbG9zdCBkdXJpbmcgbG9nb3V0Li5zbyBpdCBjb3VsZCBtZWFuIHdlIGhhdmUgbm90IGxvZ291dCBvbiBzZXJ2ZXIgc2lkZS5cbiAgICAgICAgICAgIHNvY2tldC5lbWl0KCdsb2dvdXQnLCB1c2VyVG9rZW4pO1xuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gZ2V0Rm9yVmFsaWRDb25uZWN0aW9uKCkge1xuICAgICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcbiAgICAgICAgICAgIGlmIChzZXNzaW9uVXNlci5jb25uZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHNvY2tldCk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIC8vIGJlaW5nIHRoZSBzY2VuZSwgc29ja2V0LmlvIGlzIHRyeWluZyB0byByZWNvbm5lY3QgYW5kIGF1dGhlbnRpY2F0ZSBpZiB0aGUgY29ubmVjdGlvbiB3YXMgbG9zdDtcbiAgICAgICAgICAgICAgICByZWNvbm5lY3QoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KCdVU0VSX05PVF9DT05ORUNURUQnKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gcmVjb25uZWN0KCkge1xuICAgICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgICAgICAgaWYgKHNlc3Npb25Vc2VyLmNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIGlmIHRoZSByZXNwb25zZSBkb2VzIG5vdCBjb21lIHF1aWNrLi5sZXQncyBnaXZlIHVwIHNvIHdlIGRvbid0IGdldCBzdHVjayB3YWl0aW5nXG4gICAgICAgICAgICAvLyBAVE9ETzpvdGhlciB3YXkgaXMgdG8gd2F0Y2ggZm9yIGEgY29ubmVjdGlvbiBlcnJvci4uLlxuICAgICAgICAgICAgdmFyIGFjY2VwdGFibGVEZWxheTtcbiAgICAgICAgICAgIHZhciBvZmYgPSAkcm9vdFNjb3BlLiRvbigndXNlcl9jb25uZWN0ZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgb2ZmKCk7XG4gICAgICAgICAgICAgICAgaWYgKGFjY2VwdGFibGVEZWxheSkge1xuICAgICAgICAgICAgICAgICAgICAkdGltZW91dC5jYW5jZWwoYWNjZXB0YWJsZURlbGF5KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIGFjY2VwdGFibGVEZWxheSA9ICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBvZmYoKTtcbiAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoJ1RJTUVPVVQnKTtcbiAgICAgICAgICAgIH0sIHJlY29ubmVjdGlvbk1heFRpbWUgfCAxMDAwICogNjApO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHNldHVwKCkge1xuICAgICAgICAgICAgaWYgKHNvY2tldCkge1xuICAgICAgICAgICAgICAgIC8vYWxyZWFkeSBjYWxsZWQuLi5cbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB2YXIgdG9rZW5WYWxpZGl0eVRpbWVvdXQ7XG4gICAgICAgICAgICAvLyBlc3RhYmxpc2ggY29ubmVjdGlvbiB3aXRob3V0IHBhc3NpbmcgdGhlIHRva2VuIChzbyB0aGF0IGl0IGlzIG5vdCB2aXNpYmxlIGluIHRoZSBsb2cpXG4gICAgICAgICAgICBzb2NrZXQgPSBpby5jb25uZWN0KHtcbiAgICAgICAgICAgICAgICAnZm9yY2VOZXcnOiB0cnVlLFxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNvY2tldFxuICAgICAgICAgICAgICAgIC5vbignY29ubmVjdCcsIG9uQ29ubmVjdClcbiAgICAgICAgICAgICAgICAub24oJ2F1dGhlbnRpY2F0ZWQnLCBvbkF1dGhlbnRpY2F0ZWQpXG4gICAgICAgICAgICAgICAgLm9uKCd1bmF1dGhvcml6ZWQnLCBvblVuYXV0aG9yaXplZClcbiAgICAgICAgICAgICAgICAub24oJ2xvZ2dlZF9vdXQnLCBvbkxvZ091dClcbiAgICAgICAgICAgICAgICAub24oJ2Rpc2Nvbm5lY3QnLCBvbkRpc2Nvbm5lY3QpO1xuXG4gICAgICAgICAgICAvLyBUT0RPOiB0aGlzIGZvbGxvd293aW5nIGV2ZW50IGlzIHN0aWxsIHVzZWQuLi4uLlxuICAgICAgICAgICAgc29ja2V0XG4gICAgICAgICAgICAgICAgLm9uKCdjb25uZWN0X2Vycm9yJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3QoKSB7XG4gICAgICAgICAgICAgICAgLy8gdGhlIHNvY2tldCBpcyBjb25uZWN0ZWQsIHRpbWUgdG8gcGFzcyB0aGUgdG9rZW4gdG8gYXV0aGVudGljYXRlIGFzYXBcbiAgICAgICAgICAgICAgICAvLyBiZWNhdXNlIHRoZSB0b2tlbiBpcyBhYm91dCB0byBleHBpcmUuLi5pZiBpdCBleHBpcmVzIHdlIHdpbGwgaGF2ZSB0byByZWxvZyBpblxuICAgICAgICAgICAgICAgIHNldENvbm5lY3Rpb25TdGF0dXMoZmFsc2UpO1xuICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KCdhdXRoZW50aWNhdGUnLCB7IHRva2VuOiB1c2VyVG9rZW4gfSk7IC8vIHNlbmQgdGhlIGp3dFxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkRpc2Nvbm5lY3QoKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnU2Vzc2lvbiBkaXNjb25uZWN0ZWQnKTtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gb25BdXRoZW50aWNhdGVkKHJlZnJlc2hUb2tlbikge1xuICAgICAgICAgICAgICAgIGNsZWFyVG9rZW5UaW1lb3V0KCk7XG4gICAgICAgICAgICAgICAgLy8gdGhlIHNlcnZlciBjb25maXJtZWQgdGhhdCB0aGUgdG9rZW4gaXMgdmFsaWQuLi53ZSBhcmUgZ29vZCB0byBnb1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ2F1dGhlbnRpY2F0ZWQsIHJlY2VpdmVkIG5ldyB0b2tlbjogJyArIChyZWZyZXNoVG9rZW4gIT0gdXNlclRva2VuKSk7XG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnRva2VuID0gcmVmcmVzaFRva2VuO1xuICAgICAgICAgICAgICAgIHVzZXJUb2tlbiA9IHJlZnJlc2hUb2tlbjtcbiAgICAgICAgICAgICAgICBzZXRMb2dpblVzZXIodXNlclRva2VuKTtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKHRydWUpO1xuICAgICAgICAgICAgICAgIHJlcXVlc3ROZXdUb2tlbkJlZm9yZUV4cGlyYXRpb24odXNlclRva2VuKTtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoJ3VzZXJfY29ubmVjdGVkJyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uTG9nT3V0KCkge1xuICAgICAgICAgICAgICAgIGNsZWFyVG9rZW5UaW1lb3V0KCk7XG4gICAgICAgICAgICAgICAgLy8gdG9rZW4gaXMgbm8gbG9uZ2VyIGF2YWlsYWJsZS5cbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UudG9rZW4gPSBudWxsO1xuICAgICAgICAgICAgICAgIHNldENvbm5lY3Rpb25TdGF0dXMoZmFsc2UpO1xuICAgICAgICAgICAgICAgIHJlZGlyZWN0KGxvZ291dFVybCB8fCBsb2dpblVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uVW5hdXRob3JpemVkKG1zZykge1xuICAgICAgICAgICAgICAgIGNsZWFyVG9rZW5UaW1lb3V0KCk7XG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygndW5hdXRob3JpemVkOiAnICsgSlNPTi5zdHJpbmdpZnkobXNnLmRhdGEpKTtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICByZWRpcmVjdChsb2dpblVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHNldENvbm5lY3Rpb25TdGF0dXMoY29ubmVjdGVkKSB7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIuY29ubmVjdGVkID0gY29ubmVjdGVkO1xuICAgICAgICAgICAgICAgIC8vY29uc29sZS5kZWJ1ZyhcIkNvbm5lY3Rpb24gc3RhdHVzOlwiICsgSlNPTi5zdHJpbmdpZnkoc2Vzc2lvblVzZXIpKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gc2V0TG9naW5Vc2VyKHRva2VuKSB7XG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWQgPSBkZWNvZGUodG9rZW4pO1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmlkID0gcGF5bG9hZC5pZDtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5kaXNwbGF5ID0gcGF5bG9hZC5kaXNwbGF5O1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmZpcnN0TmFtZSA9IHBheWxvYWQuZmlyc3ROYW1lO1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmxhc3ROYW1lID0gcGF5bG9hZC5sYXN0TmFtZTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5yb2xlID0gcGF5bG9hZC5yb2xlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBjbGVhclRva2VuVGltZW91dCgpIHtcbiAgICAgICAgICAgICAgICBpZiAodG9rZW5WYWxpZGl0eVRpbWVvdXQpIHtcbiAgICAgICAgICAgICAgICAgICAgJHRpbWVvdXQuY2FuY2VsKHRva2VuVmFsaWRpdHlUaW1lb3V0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIGRlY29kZSh0b2tlbikge1xuICAgICAgICAgICAgICAgIHZhciBiYXNlNjRVcmwgPSB0b2tlbi5zcGxpdCgnLicpWzFdO1xuICAgICAgICAgICAgICAgIHZhciBiYXNlNjQgPSBiYXNlNjRVcmwucmVwbGFjZSgnLScsICcrJykucmVwbGFjZSgnXycsICcvJyk7XG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWQgPSBKU09OLnBhcnNlKCR3aW5kb3cuYXRvYihiYXNlNjQpKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcGF5bG9hZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gcmVxdWVzdE5ld1Rva2VuQmVmb3JlRXhwaXJhdGlvbih0b2tlbikge1xuICAgICAgICAgICAgICAgIC8vIHJlcXVlc3QgYSBsaXR0bGUgYmVmb3JlLi4uXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWQgPSBkZWNvZGUodG9rZW4sIHsgY29tcGxldGU6IGZhbHNlIH0pO1xuXG4gICAgICAgICAgICAgICAgdmFyIGluaXRpYWwgPSBwYXlsb2FkLmR1cjtcblxuICAgICAgICAgICAgICAgIHZhciBkdXJhdGlvbiA9IChpbml0aWFsICogOTAgLyAxMDApIHwgMDtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdTY2hlZHVsZSB0byByZXF1ZXN0IGEgbmV3IHRva2VuIGluICcgKyBkdXJhdGlvbiArICcgc2Vjb25kcyAodG9rZW4gZHVyYXRpb246JyArIGluaXRpYWwgKyAnKScpO1xuICAgICAgICAgICAgICAgIHRva2VuVmFsaWRpdHlUaW1lb3V0ID0gJHRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdUaW1lIHRvIHJlcXVlc3QgbmV3IHRva2VuICcgKyBpbml0aWFsKTtcbiAgICAgICAgICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2F1dGhlbnRpY2F0ZScsIHsgdG9rZW46IHRva2VuIH0pO1xuICAgICAgICAgICAgICAgICAgICAvLyBOb3RlOiBJZiBjb21tdW5pY2F0aW9uIGNyYXNoZXMgcmlnaHQgYWZ0ZXIgd2UgZW1pdHRlZCBhbmQgd2hlbiBzZXJ2ZXJzIGlzIHNlbmRpbmcgYmFjayB0aGUgdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgIC8vIHdoZW4gdGhlIGNsaWVudCByZWVzdGFibGlzaGVzIHRoZSBjb25uZWN0aW9uLCB3ZSB3b3VsZCBoYXZlIHRvIGxvZ2luIGJlY2F1c2UgdGhlIHByZXZpb3VzIHRva2VuIHdvdWxkIGJlIGludmFsaWRhdGVkLlxuICAgICAgICAgICAgICAgIH0sIGR1cmF0aW9uICogMTAwMCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZXRyaWV2ZVRva2VuKCkge1xuICAgICAgICAgICAgdmFyIHVzZXJUb2tlbiA9ICRsb2NhdGlvbi5zZWFyY2goKS50b2tlbjtcbiAgICAgICAgICAgIGlmICh1c2VyVG9rZW4pIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdVc2luZyB0b2tlbiBwYXNzZWQgZHVyaW5nIHJlZGlyZWN0aW9uOiAnICsgdXNlclRva2VuKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgdXNlclRva2VuID0gbG9jYWxTdG9yYWdlLnRva2VuO1xuICAgICAgICAgICAgICAgIGlmICh1c2VyVG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnVXNpbmcgVG9rZW4gaW4gbG9jYWwgc3RvcmFnZTogJyArIHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcblxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB1c2VyVG9rZW47XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZWRpcmVjdCh1cmwpIHtcbiAgICAgICAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZXBsYWNlKHVybCB8fCAnYmFkVXJsLmh0bWwnKTtcbiAgICAgICAgfVxuICAgIH07XG59XG59KCkpO1xuXG4oZnVuY3Rpb24oKSB7XG5cInVzZSBzdHJpY3RcIjtcblxuLyoqIFxuICogVGhpcyBzZXJ2aWNlIGFsbG93cyB5b3VyIGFwcGxpY2F0aW9uIGNvbnRhY3QgdGhlIHdlYnNvY2tldCBhcGkuXG4gKiBcbiAqIEl0IHdpbGwgZW5zdXJlIHRoYXQgdGhlIGNvbm5lY3Rpb24gaXMgYXZhaWxhYmxlIGFuZCB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQgYmVmb3JlIGZldGNoaW5nIGRhdGEuXG4gKiBcbiAqL1xuYW5ndWxhclxuICAgIC5tb2R1bGUoJ3NvY2tldGlvLWF1dGgnKVxuICAgIC5zZXJ2aWNlKCckc29ja2V0aW8nLCBzb2NrZXRTZXJ2aWNlKTtcblxuZnVuY3Rpb24gc29ja2V0U2VydmljZSgkcm9vdFNjb3BlLCAkcSwgJGF1dGgpIHtcblxuICAgIHRoaXMub24gPSBvbjtcbiAgICB0aGlzLmVtaXQgPSBlbWl0O1xuICAgIHRoaXMubG9nb3V0ID0gJGF1dGgubG9nb3V0O1xuICAgIHRoaXMuZmV0Y2ggPSBmZXRjaDtcbiAgICB0aGlzLnBvc3QgPSBwb3N0O1xuICAgIHRoaXMubm90aWZ5ID0gbm90aWZ5O1xuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vL1xuICAgIGZ1bmN0aW9uIG9uKGV2ZW50TmFtZSwgY2FsbGJhY2spIHtcbiAgICAgICAgJGF1dGguY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKHNvY2tldCkge1xuICAgICAgICAgICAgc29ja2V0Lm9uKGV2ZW50TmFtZSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciBhcmdzID0gYXJndW1lbnRzO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGFwcGx5KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2suYXBwbHkoc29ja2V0LCBhcmdzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG4gICAgLy8gZGVwcmVjYXRlZCwgdXNlIHBvc3Qvbm90aWZ5XG4gICAgZnVuY3Rpb24gZW1pdChldmVudE5hbWUsIGRhdGEsIGNhbGxiYWNrKSB7XG4gICAgICAgICRhdXRoLmNvbm5lY3QoKS50aGVuKGZ1bmN0aW9uIChzb2NrZXQpIHtcbiAgICAgICAgICAgIHNvY2tldC5lbWl0KGV2ZW50TmFtZSwgZGF0YSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciBhcmdzID0gYXJndW1lbnRzO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGFwcGx5KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGNhbGxiYWNrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjay5hcHBseShzb2NrZXQsIGFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogZmV0Y2ggZGF0YSB0aGUgd2F5IHdlIGNhbGwgYW4gYXBpIFxuICAgICAqIGh0dHA6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvMjA2ODUyMDgvd2Vic29ja2V0LXRyYW5zcG9ydC1yZWxpYWJpbGl0eS1zb2NrZXQtaW8tZGF0YS1sb3NzLWR1cmluZy1yZWNvbm5lY3Rpb25cbiAgICAgKiBcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBmZXRjaChvcGVyYXRpb24sIGRhdGEpIHtcbiAgICAgICAgY29uc29sZS5kZWJ1ZygnRmV0Y2hpbmcgJyArIG9wZXJhdGlvbiArICcuLi4nKTtcbiAgICAgICAgcmV0dXJuIHNvY2tldEVtaXQob3BlcmF0aW9uLCBkYXRhKVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIG5vdGlmeSBpcyBzaW1pbGFyIHRvIGZldGNoIGJ1dCBtb3JlIG1lYW5pbmdmdWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBub3RpZnkob3BlcmF0aW9uLCBkYXRhKSB7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ05vdGlmeWluZyAnICsgb3BlcmF0aW9uICsgJy4uLicpO1xuICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogcG9zdCB3aWxsIGhhbmRsZSBsYXRlciBvbiwgZHVwbGljYXRlIHJlY29yZCBieSBwcm92aWRpbmcgYSBzdGFtcC5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwb3N0KG9wZXJhdGlvbiwgZGF0YSkge1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdQb3N0aW5nICcgKyBvcGVyYXRpb24gKyAnLi4uJyk7XG4gICAgICAgIHJldHVybiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSlcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSkge1xuXG4gICAgICAgIHJldHVybiAkYXV0aC5jb25uZWN0KClcbiAgICAgICAgICAgIC50aGVuKG9uQ29ubmVjdGlvblN1Y2Nlc3MsIG9uQ29ubmVjdGlvbkVycm9yKVxuICAgICAgICAgICAgOy8vIC5jYXRjaChvbkNvbm5lY3Rpb25FcnJvcik7XG5cbiAgICAgICAgLy8vLy8vLy8vLy8vXG4gICAgICAgIGZ1bmN0aW9uIG9uQ29ubmVjdGlvblN1Y2Nlc3Moc29ja2V0KSB7XG4gICAgICAgICAgICAvLyBidXQgd2hhdCBpZiB3ZSBoYXZlIG5vdCBjb25uZWN0aW9uIGJlZm9yZSB0aGUgZW1pdCwgaXQgd2lsbCBxdWV1ZSBjYWxsLi4ubm90IHNvIGdvb2QuICAgICAgICBcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG4gICAgICAgICAgICBzb2NrZXQuZW1pdCgnYXBpJywgb3BlcmF0aW9uLCBkYXRhLCBmdW5jdGlvbiAocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3VsdC5jb2RlKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ0Vycm9yIG9uICcgKyBvcGVyYXRpb24gKyAnIC0+JyArIEpTT04uc3RyaW5naWZ5KHJlc3VsdCkpO1xuICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoeyBjb2RlOiByZXN1bHQuY29kZSwgZGVzY3JpcHRpb246IHJlc3VsdC5kYXRhIH0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXN1bHQuZGF0YSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIG9uQ29ubmVjdGlvbkVycm9yKGVycikge1xuICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IGNvZGU6ICdDT05ORUNUSU9OX0VSUicsIGRlc2NyaXB0aW9uOiBlcnIgfSk7XG4gICAgICAgIH1cbiAgICB9XG59XG59KCkpO1xuXG4iLCJhbmd1bGFyLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcsIFtdKTtcbiIsIlxuLyoqIFxuICogVGhpcyBwcm92aWRlciBoYW5kbGVzIHRoZSBoYW5kc2hha2UgdG8gYXV0aGVudGljYXRlIGEgdXNlciBhbmQgbWFpbnRhaW4gYSBzZWN1cmUgd2ViIHNvY2tldCBjb25uZWN0aW9uIHZpYSB0b2tlbnMuXG4gKiBJdCBhbHNvIHNldHMgdGhlIGxvZ2luIGFuZCBsb2dvdXQgdXJsIHBhcnRpY2lwYXRpbmcgaW4gdGhlIGF1dGhlbnRpY2F0aW9uLlxuICogXG4gKiBcbiAqIHVzYWdlIGV4YW1wbGVzOlxuICogXG4gKiBJbiB0aGUgY29uZmlnIG9mIHRoZSBhcHAgbW9kdWxlOlxuICogc29ja2V0U2VydmljZVByb3ZpZGVyLnNldExvZ2luVXJsKCcvYWNjZXNzIy9sb2dpbicpO1xuICogc29ja2V0U2VydmljZVByb3ZpZGVyLnNldExvZ291dFVybCgnL2FjY2VzcyMvbG9naW4nKTtcbiAqIHNvY2tldFNlcnZpY2VQcm92aWRlci5zZXRSZWNvbm5lY3Rpb25NYXhUaW1lSW5TZWNzKDE1KTtcbiAqIFRoaXMgZGVmaW5lcyBob3cgbXVjaCB0aW1lIHdlIGNhbiB3YWl0IHRvIGVzdGFibGlzaCBhIHN1Y2Nlc3N1bCBjb25uZWN0aW9uIGJlZm9yZSByZWplY3RpbmcgdGhlIGNvbm5lY3Rpb24gKHNvY2tldFNlcnZpY2UuY29ubmVjdElPKSB3aXRoIGEgdGltZW91dFxuICogIFxuICogQmVmb3JlIGFueSBzb2NrZXQgdXNlIGluIHlvdXIgc2VydmljZXMgb3IgcmVzb2x2ZSBibG9ja3MsIGNvbm5lY3QoKSBtYWtlcyBzdXJlIHRoYXQgd2UgaGF2ZSBhbiBlc3RhYmxpc2hlZCBhdXRoZW50aWNhdGVkIGNvbm5lY3Rpb24gYnkgdXNpbmcgdGhlIGZvbGxvd2luZzpcbiAqIHNvY2tldFNlcnZpY2UuY29ubmVjdCgpLnRoZW4oXG4gKiBmdW5jdGlvbihzb2NrZXQpeyAuLi4gc29ja2V0LmVtaXQoKS4uIH0pLmNhdGNoKGZ1bmN0aW9uKGVycikgey4uLn0pXG4gKiBcbiAqIFxuICovXG5hbmd1bGFyXG4gICAgLm1vZHVsZSgnc29ja2V0aW8tYXV0aCcpXG4gICAgLnByb3ZpZGVyKCckYXV0aCcsIGF1dGhQcm92aWRlcik7XG5cbmZ1bmN0aW9uIGF1dGhQcm92aWRlcigpIHtcblxuICAgIHZhciBsb2dpblVybCwgbG9nb3V0VXJsLCByZWNvbm5lY3Rpb25NYXhUaW1lO1xuXG4gICAgdGhpcy5zZXRMb2dpblVybCA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICBsb2dpblVybCA9IHZhbHVlO1xuICAgIH07XG4gICAgXG4gICAgdGhpcy5zZXRMb2dvdXRVcmwgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgbG9nb3V0VXJsID0gdmFsdWU7XG4gICAgfTtcblxuICAgIHRoaXMuc2V0UmVjb25uZWN0aW9uTWF4VGltZUluU2VjcyA9IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICByZWNvbm5lY3Rpb25NYXhUaW1lID0gdmFsdWUgKiAxMDAwO1xuICAgIH07XG5cbiAgICB0aGlzLiRnZXQgPSBmdW5jdGlvbiAoJHJvb3RTY29wZSwgJGxvY2F0aW9uLCAkdGltZW91dCwgJHEsICR3aW5kb3cpIHtcblxuICAgICAgICB2YXIgc29ja2V0O1xuICAgICAgICB2YXIgdXNlclRva2VuID0gcmV0cmlldmVUb2tlbigpO1xuICAgICAgICB2YXIgc2Vzc2lvblVzZXIgPSB7fTtcbiAgICAgICAgJHJvb3RTY29wZS5zZXNzaW9uVXNlciA9IHNlc3Npb25Vc2VyO1xuXG4gICAgICAgIGlmICghdXNlclRva2VuKSB7XG4gICAgICAgICAgICAvLyBAVE9ETzogdGhpcyByaWdodCB3YXkgdG8gcmVkaXJlY3QgaWYgd2UgaGF2ZSBubyB0b2tlbiB3aGVuIHdlIHJlZnJlc2ggb3IgaGl0IHRoZSBhcHAuXG4gICAgICAgICAgICAvLyAgcmVkaXJlY3QobG9naW5VcmwpO1xuICAgICAgICAgICAgLy8gYnV0IGl0IHdvdWxkIHByZXZlbnQgbW9zdCB1bml0IHRlc3RzIGZyb20gcnVubmluZyBiZWNhdXNlIHRoaXMgbW9kdWxlIGlzIHRpZ2hseSBjb3VwbGVkIHdpdGggYWxsIHVuaXQgdGVzdHMgKGRlcGVuZHMgb24gaXQpYXQgdGhpcyB0aW1lIDpcblxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnRva2VuID0gdXNlclRva2VuO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBjb25uZWN0OiBjb25uZWN0LFxuICAgICAgICAgICAgbG9nb3V0OiBsb2dvdXRcbiAgICAgICAgfTtcblxuICAgICAgICAvLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgICAgIC8qKlxuICAgICAgICAgKiByZXR1cm5zIGEgcHJvbWlzZSBcbiAgICAgICAgICogdGhlIHN1Y2Nlc3MgZnVuY3Rpb24gcmVjZWl2ZXMgdGhlIHNvY2tldCBhcyBhIHBhcmFtZXRlclxuICAgICAgICAgKi9cbiAgICAgICAgZnVuY3Rpb24gY29ubmVjdCgpIHtcbiAgICAgICAgICAgIGlmICghc29ja2V0KSB7XG4gICAgICAgICAgICAgICAgc2V0dXAoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBnZXRGb3JWYWxpZENvbm5lY3Rpb24oKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIGxvZ291dCgpIHtcbiAgICAgICAgICAgIC8vIGNvbm5lY3Rpb24gY291bGQgYmUgbG9zdCBkdXJpbmcgbG9nb3V0Li5zbyBpdCBjb3VsZCBtZWFuIHdlIGhhdmUgbm90IGxvZ291dCBvbiBzZXJ2ZXIgc2lkZS5cbiAgICAgICAgICAgIHNvY2tldC5lbWl0KCdsb2dvdXQnLCB1c2VyVG9rZW4pO1xuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gZ2V0Rm9yVmFsaWRDb25uZWN0aW9uKCkge1xuICAgICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcbiAgICAgICAgICAgIGlmIChzZXNzaW9uVXNlci5jb25uZWN0ZWQpIHtcbiAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZXNvbHZlKHNvY2tldCk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIC8vIGJlaW5nIHRoZSBzY2VuZSwgc29ja2V0LmlvIGlzIHRyeWluZyB0byByZWNvbm5lY3QgYW5kIGF1dGhlbnRpY2F0ZSBpZiB0aGUgY29ubmVjdGlvbiB3YXMgbG9zdDtcbiAgICAgICAgICAgICAgICByZWNvbm5lY3QoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgICAgIH0pLmNhdGNoKGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVqZWN0KCdVU0VSX05PVF9DT05ORUNURUQnKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBkZWZlcnJlZC5wcm9taXNlO1xuICAgICAgICB9XG5cbiAgICAgICAgZnVuY3Rpb24gcmVjb25uZWN0KCkge1xuICAgICAgICAgICAgdmFyIGRlZmVycmVkID0gJHEuZGVmZXIoKTtcblxuICAgICAgICAgICAgaWYgKHNlc3Npb25Vc2VyLmNvbm5lY3RlZCkge1xuICAgICAgICAgICAgICAgIGRlZmVycmVkLnJlc29sdmUoc29ja2V0KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIGlmIHRoZSByZXNwb25zZSBkb2VzIG5vdCBjb21lIHF1aWNrLi5sZXQncyBnaXZlIHVwIHNvIHdlIGRvbid0IGdldCBzdHVjayB3YWl0aW5nXG4gICAgICAgICAgICAvLyBAVE9ETzpvdGhlciB3YXkgaXMgdG8gd2F0Y2ggZm9yIGEgY29ubmVjdGlvbiBlcnJvci4uLlxuICAgICAgICAgICAgdmFyIGFjY2VwdGFibGVEZWxheTtcbiAgICAgICAgICAgIHZhciBvZmYgPSAkcm9vdFNjb3BlLiRvbigndXNlcl9jb25uZWN0ZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgb2ZmKCk7XG4gICAgICAgICAgICAgICAgaWYgKGFjY2VwdGFibGVEZWxheSkge1xuICAgICAgICAgICAgICAgICAgICAkdGltZW91dC5jYW5jZWwoYWNjZXB0YWJsZURlbGF5KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShzb2NrZXQpO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIGFjY2VwdGFibGVEZWxheSA9ICR0aW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBvZmYoKTtcbiAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoJ1RJTUVPVVQnKTtcbiAgICAgICAgICAgIH0sIHJlY29ubmVjdGlvbk1heFRpbWUgfCAxMDAwICogNjApO1xuXG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIHNldHVwKCkge1xuICAgICAgICAgICAgaWYgKHNvY2tldCkge1xuICAgICAgICAgICAgICAgIC8vYWxyZWFkeSBjYWxsZWQuLi5cbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB2YXIgdG9rZW5WYWxpZGl0eVRpbWVvdXQ7XG4gICAgICAgICAgICAvLyBlc3RhYmxpc2ggY29ubmVjdGlvbiB3aXRob3V0IHBhc3NpbmcgdGhlIHRva2VuIChzbyB0aGF0IGl0IGlzIG5vdCB2aXNpYmxlIGluIHRoZSBsb2cpXG4gICAgICAgICAgICBzb2NrZXQgPSBpby5jb25uZWN0KHtcbiAgICAgICAgICAgICAgICAnZm9yY2VOZXcnOiB0cnVlLFxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNvY2tldFxuICAgICAgICAgICAgICAgIC5vbignY29ubmVjdCcsIG9uQ29ubmVjdClcbiAgICAgICAgICAgICAgICAub24oJ2F1dGhlbnRpY2F0ZWQnLCBvbkF1dGhlbnRpY2F0ZWQpXG4gICAgICAgICAgICAgICAgLm9uKCd1bmF1dGhvcml6ZWQnLCBvblVuYXV0aG9yaXplZClcbiAgICAgICAgICAgICAgICAub24oJ2xvZ2dlZF9vdXQnLCBvbkxvZ091dClcbiAgICAgICAgICAgICAgICAub24oJ2Rpc2Nvbm5lY3QnLCBvbkRpc2Nvbm5lY3QpO1xuXG4gICAgICAgICAgICAvLyBUT0RPOiB0aGlzIGZvbGxvd293aW5nIGV2ZW50IGlzIHN0aWxsIHVzZWQuLi4uLlxuICAgICAgICAgICAgc29ja2V0XG4gICAgICAgICAgICAgICAgLm9uKCdjb25uZWN0X2Vycm9yJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkNvbm5lY3QoKSB7XG4gICAgICAgICAgICAgICAgLy8gdGhlIHNvY2tldCBpcyBjb25uZWN0ZWQsIHRpbWUgdG8gcGFzcyB0aGUgdG9rZW4gdG8gYXV0aGVudGljYXRlIGFzYXBcbiAgICAgICAgICAgICAgICAvLyBiZWNhdXNlIHRoZSB0b2tlbiBpcyBhYm91dCB0byBleHBpcmUuLi5pZiBpdCBleHBpcmVzIHdlIHdpbGwgaGF2ZSB0byByZWxvZyBpblxuICAgICAgICAgICAgICAgIHNldENvbm5lY3Rpb25TdGF0dXMoZmFsc2UpO1xuICAgICAgICAgICAgICAgIHNvY2tldC5lbWl0KCdhdXRoZW50aWNhdGUnLCB7IHRva2VuOiB1c2VyVG9rZW4gfSk7IC8vIHNlbmQgdGhlIGp3dFxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbkRpc2Nvbm5lY3QoKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnU2Vzc2lvbiBkaXNjb25uZWN0ZWQnKTtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gb25BdXRoZW50aWNhdGVkKHJlZnJlc2hUb2tlbikge1xuICAgICAgICAgICAgICAgIGNsZWFyVG9rZW5UaW1lb3V0KCk7XG4gICAgICAgICAgICAgICAgLy8gdGhlIHNlcnZlciBjb25maXJtZWQgdGhhdCB0aGUgdG9rZW4gaXMgdmFsaWQuLi53ZSBhcmUgZ29vZCB0byBnb1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ2F1dGhlbnRpY2F0ZWQsIHJlY2VpdmVkIG5ldyB0b2tlbjogJyArIChyZWZyZXNoVG9rZW4gIT0gdXNlclRva2VuKSk7XG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnRva2VuID0gcmVmcmVzaFRva2VuO1xuICAgICAgICAgICAgICAgIHVzZXJUb2tlbiA9IHJlZnJlc2hUb2tlbjtcbiAgICAgICAgICAgICAgICBzZXRMb2dpblVzZXIodXNlclRva2VuKTtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKHRydWUpO1xuICAgICAgICAgICAgICAgIHJlcXVlc3ROZXdUb2tlbkJlZm9yZUV4cGlyYXRpb24odXNlclRva2VuKTtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoJ3VzZXJfY29ubmVjdGVkJyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uTG9nT3V0KCkge1xuICAgICAgICAgICAgICAgIGNsZWFyVG9rZW5UaW1lb3V0KCk7XG4gICAgICAgICAgICAgICAgLy8gdG9rZW4gaXMgbm8gbG9uZ2VyIGF2YWlsYWJsZS5cbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UudG9rZW4gPSBudWxsO1xuICAgICAgICAgICAgICAgIHNldENvbm5lY3Rpb25TdGF0dXMoZmFsc2UpO1xuICAgICAgICAgICAgICAgIHJlZGlyZWN0KGxvZ291dFVybCB8fCBsb2dpblVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIG9uVW5hdXRob3JpemVkKG1zZykge1xuICAgICAgICAgICAgICAgIGNsZWFyVG9rZW5UaW1lb3V0KCk7XG4gICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygndW5hdXRob3JpemVkOiAnICsgSlNPTi5zdHJpbmdpZnkobXNnLmRhdGEpKTtcbiAgICAgICAgICAgICAgICBzZXRDb25uZWN0aW9uU3RhdHVzKGZhbHNlKTtcbiAgICAgICAgICAgICAgICByZWRpcmVjdChsb2dpblVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIHNldENvbm5lY3Rpb25TdGF0dXMoY29ubmVjdGVkKSB7XG4gICAgICAgICAgICAgICAgc2Vzc2lvblVzZXIuY29ubmVjdGVkID0gY29ubmVjdGVkO1xuICAgICAgICAgICAgICAgIC8vY29uc29sZS5kZWJ1ZyhcIkNvbm5lY3Rpb24gc3RhdHVzOlwiICsgSlNPTi5zdHJpbmdpZnkoc2Vzc2lvblVzZXIpKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gc2V0TG9naW5Vc2VyKHRva2VuKSB7XG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWQgPSBkZWNvZGUodG9rZW4pO1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmlkID0gcGF5bG9hZC5pZDtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5kaXNwbGF5ID0gcGF5bG9hZC5kaXNwbGF5O1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmZpcnN0TmFtZSA9IHBheWxvYWQuZmlyc3ROYW1lO1xuICAgICAgICAgICAgICAgIHNlc3Npb25Vc2VyLmxhc3ROYW1lID0gcGF5bG9hZC5sYXN0TmFtZTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uVXNlci5yb2xlID0gcGF5bG9hZC5yb2xlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmdW5jdGlvbiBjbGVhclRva2VuVGltZW91dCgpIHtcbiAgICAgICAgICAgICAgICBpZiAodG9rZW5WYWxpZGl0eVRpbWVvdXQpIHtcbiAgICAgICAgICAgICAgICAgICAgJHRpbWVvdXQuY2FuY2VsKHRva2VuVmFsaWRpdHlUaW1lb3V0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZ1bmN0aW9uIGRlY29kZSh0b2tlbikge1xuICAgICAgICAgICAgICAgIHZhciBiYXNlNjRVcmwgPSB0b2tlbi5zcGxpdCgnLicpWzFdO1xuICAgICAgICAgICAgICAgIHZhciBiYXNlNjQgPSBiYXNlNjRVcmwucmVwbGFjZSgnLScsICcrJykucmVwbGFjZSgnXycsICcvJyk7XG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWQgPSBKU09OLnBhcnNlKCR3aW5kb3cuYXRvYihiYXNlNjQpKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcGF5bG9hZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZnVuY3Rpb24gcmVxdWVzdE5ld1Rva2VuQmVmb3JlRXhwaXJhdGlvbih0b2tlbikge1xuICAgICAgICAgICAgICAgIC8vIHJlcXVlc3QgYSBsaXR0bGUgYmVmb3JlLi4uXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWQgPSBkZWNvZGUodG9rZW4sIHsgY29tcGxldGU6IGZhbHNlIH0pO1xuXG4gICAgICAgICAgICAgICAgdmFyIGluaXRpYWwgPSBwYXlsb2FkLmR1cjtcblxuICAgICAgICAgICAgICAgIHZhciBkdXJhdGlvbiA9IChpbml0aWFsICogOTAgLyAxMDApIHwgMDtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdTY2hlZHVsZSB0byByZXF1ZXN0IGEgbmV3IHRva2VuIGluICcgKyBkdXJhdGlvbiArICcgc2Vjb25kcyAodG9rZW4gZHVyYXRpb246JyArIGluaXRpYWwgKyAnKScpO1xuICAgICAgICAgICAgICAgIHRva2VuVmFsaWRpdHlUaW1lb3V0ID0gJHRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdUaW1lIHRvIHJlcXVlc3QgbmV3IHRva2VuICcgKyBpbml0aWFsKTtcbiAgICAgICAgICAgICAgICAgICAgc29ja2V0LmVtaXQoJ2F1dGhlbnRpY2F0ZScsIHsgdG9rZW46IHRva2VuIH0pO1xuICAgICAgICAgICAgICAgICAgICAvLyBOb3RlOiBJZiBjb21tdW5pY2F0aW9uIGNyYXNoZXMgcmlnaHQgYWZ0ZXIgd2UgZW1pdHRlZCBhbmQgd2hlbiBzZXJ2ZXJzIGlzIHNlbmRpbmcgYmFjayB0aGUgdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgIC8vIHdoZW4gdGhlIGNsaWVudCByZWVzdGFibGlzaGVzIHRoZSBjb25uZWN0aW9uLCB3ZSB3b3VsZCBoYXZlIHRvIGxvZ2luIGJlY2F1c2UgdGhlIHByZXZpb3VzIHRva2VuIHdvdWxkIGJlIGludmFsaWRhdGVkLlxuICAgICAgICAgICAgICAgIH0sIGR1cmF0aW9uICogMTAwMCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZXRyaWV2ZVRva2VuKCkge1xuICAgICAgICAgICAgdmFyIHVzZXJUb2tlbiA9ICRsb2NhdGlvbi5zZWFyY2goKS50b2tlbjtcbiAgICAgICAgICAgIGlmICh1c2VyVG9rZW4pIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdVc2luZyB0b2tlbiBwYXNzZWQgZHVyaW5nIHJlZGlyZWN0aW9uOiAnICsgdXNlclRva2VuKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgdXNlclRva2VuID0gbG9jYWxTdG9yYWdlLnRva2VuO1xuICAgICAgICAgICAgICAgIGlmICh1c2VyVG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnVXNpbmcgVG9rZW4gaW4gbG9jYWwgc3RvcmFnZTogJyArIHVzZXJUb2tlbik7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcblxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB1c2VyVG9rZW47XG4gICAgICAgIH1cblxuICAgICAgICBmdW5jdGlvbiByZWRpcmVjdCh1cmwpIHtcbiAgICAgICAgICAgIHdpbmRvdy5sb2NhdGlvbi5yZXBsYWNlKHVybCB8fCAnYmFkVXJsLmh0bWwnKTtcbiAgICAgICAgfVxuICAgIH07XG59XG5cbiIsIlxuLyoqIFxuICogVGhpcyBzZXJ2aWNlIGFsbG93cyB5b3VyIGFwcGxpY2F0aW9uIGNvbnRhY3QgdGhlIHdlYnNvY2tldCBhcGkuXG4gKiBcbiAqIEl0IHdpbGwgZW5zdXJlIHRoYXQgdGhlIGNvbm5lY3Rpb24gaXMgYXZhaWxhYmxlIGFuZCB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQgYmVmb3JlIGZldGNoaW5nIGRhdGEuXG4gKiBcbiAqL1xuYW5ndWxhclxuICAgIC5tb2R1bGUoJ3NvY2tldGlvLWF1dGgnKVxuICAgIC5zZXJ2aWNlKCckc29ja2V0aW8nLCBzb2NrZXRTZXJ2aWNlKTtcblxuZnVuY3Rpb24gc29ja2V0U2VydmljZSgkcm9vdFNjb3BlLCAkcSwgJGF1dGgpIHtcblxuICAgIHRoaXMub24gPSBvbjtcbiAgICB0aGlzLmVtaXQgPSBlbWl0O1xuICAgIHRoaXMubG9nb3V0ID0gJGF1dGgubG9nb3V0O1xuICAgIHRoaXMuZmV0Y2ggPSBmZXRjaDtcbiAgICB0aGlzLnBvc3QgPSBwb3N0O1xuICAgIHRoaXMubm90aWZ5ID0gbm90aWZ5O1xuXG4gICAgLy8vLy8vLy8vLy8vLy8vLy8vL1xuICAgIGZ1bmN0aW9uIG9uKGV2ZW50TmFtZSwgY2FsbGJhY2spIHtcbiAgICAgICAgJGF1dGguY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKHNvY2tldCkge1xuICAgICAgICAgICAgc29ja2V0Lm9uKGV2ZW50TmFtZSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciBhcmdzID0gYXJndW1lbnRzO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGFwcGx5KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2suYXBwbHkoc29ja2V0LCBhcmdzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG4gICAgLy8gZGVwcmVjYXRlZCwgdXNlIHBvc3Qvbm90aWZ5XG4gICAgZnVuY3Rpb24gZW1pdChldmVudE5hbWUsIGRhdGEsIGNhbGxiYWNrKSB7XG4gICAgICAgICRhdXRoLmNvbm5lY3QoKS50aGVuKGZ1bmN0aW9uIChzb2NrZXQpIHtcbiAgICAgICAgICAgIHNvY2tldC5lbWl0KGV2ZW50TmFtZSwgZGF0YSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHZhciBhcmdzID0gYXJndW1lbnRzO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGFwcGx5KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGNhbGxiYWNrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjay5hcHBseShzb2NrZXQsIGFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogZmV0Y2ggZGF0YSB0aGUgd2F5IHdlIGNhbGwgYW4gYXBpIFxuICAgICAqIGh0dHA6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvMjA2ODUyMDgvd2Vic29ja2V0LXRyYW5zcG9ydC1yZWxpYWJpbGl0eS1zb2NrZXQtaW8tZGF0YS1sb3NzLWR1cmluZy1yZWNvbm5lY3Rpb25cbiAgICAgKiBcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBmZXRjaChvcGVyYXRpb24sIGRhdGEpIHtcbiAgICAgICAgY29uc29sZS5kZWJ1ZygnRmV0Y2hpbmcgJyArIG9wZXJhdGlvbiArICcuLi4nKTtcbiAgICAgICAgcmV0dXJuIHNvY2tldEVtaXQob3BlcmF0aW9uLCBkYXRhKVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIG5vdGlmeSBpcyBzaW1pbGFyIHRvIGZldGNoIGJ1dCBtb3JlIG1lYW5pbmdmdWxcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBub3RpZnkob3BlcmF0aW9uLCBkYXRhKSB7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ05vdGlmeWluZyAnICsgb3BlcmF0aW9uICsgJy4uLicpO1xuICAgICAgICByZXR1cm4gc29ja2V0RW1pdChvcGVyYXRpb24sIGRhdGEpXG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogcG9zdCB3aWxsIGhhbmRsZSBsYXRlciBvbiwgZHVwbGljYXRlIHJlY29yZCBieSBwcm92aWRpbmcgYSBzdGFtcC5cbiAgICAgKi9cbiAgICBmdW5jdGlvbiBwb3N0KG9wZXJhdGlvbiwgZGF0YSkge1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdQb3N0aW5nICcgKyBvcGVyYXRpb24gKyAnLi4uJyk7XG4gICAgICAgIHJldHVybiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSlcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBzb2NrZXRFbWl0KG9wZXJhdGlvbiwgZGF0YSkge1xuXG4gICAgICAgIHJldHVybiAkYXV0aC5jb25uZWN0KClcbiAgICAgICAgICAgIC50aGVuKG9uQ29ubmVjdGlvblN1Y2Nlc3MsIG9uQ29ubmVjdGlvbkVycm9yKVxuICAgICAgICAgICAgOy8vIC5jYXRjaChvbkNvbm5lY3Rpb25FcnJvcik7XG5cbiAgICAgICAgLy8vLy8vLy8vLy8vXG4gICAgICAgIGZ1bmN0aW9uIG9uQ29ubmVjdGlvblN1Y2Nlc3Moc29ja2V0KSB7XG4gICAgICAgICAgICAvLyBidXQgd2hhdCBpZiB3ZSBoYXZlIG5vdCBjb25uZWN0aW9uIGJlZm9yZSB0aGUgZW1pdCwgaXQgd2lsbCBxdWV1ZSBjYWxsLi4ubm90IHNvIGdvb2QuICAgICAgICBcbiAgICAgICAgICAgIHZhciBkZWZlcnJlZCA9ICRxLmRlZmVyKCk7XG4gICAgICAgICAgICBzb2NrZXQuZW1pdCgnYXBpJywgb3BlcmF0aW9uLCBkYXRhLCBmdW5jdGlvbiAocmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3VsdC5jb2RlKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoJ0Vycm9yIG9uICcgKyBvcGVyYXRpb24gKyAnIC0+JyArIEpTT04uc3RyaW5naWZ5KHJlc3VsdCkpO1xuICAgICAgICAgICAgICAgICAgICBkZWZlcnJlZC5yZWplY3QoeyBjb2RlOiByZXN1bHQuY29kZSwgZGVzY3JpcHRpb246IHJlc3VsdC5kYXRhIH0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgZGVmZXJyZWQucmVzb2x2ZShyZXN1bHQuZGF0YSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gZGVmZXJyZWQucHJvbWlzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZ1bmN0aW9uIG9uQ29ubmVjdGlvbkVycm9yKGVycikge1xuICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IGNvZGU6ICdDT05ORUNUSU9OX0VSUicsIGRlc2NyaXB0aW9uOiBlcnIgfSk7XG4gICAgICAgIH1cbiAgICB9XG59XG5cbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
