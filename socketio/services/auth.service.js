
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
    .provider('$auth', authService);

function authService() {

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

    this.$get = function ($rootScope, $location, $timeout, $q, $window) {

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
    };
}

