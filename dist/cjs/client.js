"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthClient = createAuthClient;
var pkce_1 = require("./pkce");
var DEFAULT_SCOPE = 'openid profile email';
var DEFAULT_LOGIN_ATTEMPT_TTL_MS = 10 * 60 * 1000;
var DEFAULT_POST_LOGIN_PATH = '/';
var EXPIRY_MARGIN_MS = 60 * 1000;
function stripTrailingSlash(url) {
    return url.length > 0 && url.charAt(url.length - 1) === '/' ? url.slice(0, -1) : url;
}
function createAuthClient(config) {
    if (!config) {
        throw new Error('config is required');
    }
    if (!config.authServerUrl) {
        throw new Error('authServerUrl is required');
    }
    if (!config.clientId) {
        throw new Error('clientId is required');
    }
    var authServerUrl = stripTrailingSlash(config.authServerUrl);
    var clientId = config.clientId;
    var scope = config.scope || DEFAULT_SCOPE;
    var configuredRedirectUri = config.redirectUri;
    var configuredStorage = config.storage;
    var loginAttemptTtlMs = config.loginAttemptTtlMs || DEFAULT_LOGIN_ATTEMPT_TTL_MS;
    var postLoginPath = config.postLoginPath || DEFAULT_POST_LOGIN_PATH;
    var authorizePath = config.authorizePath || '/oauth/authorize';
    var tokenPath = config.tokenPath || '/oauth/token';
    var logoutPath = config.logoutPath || '/api/auth/logout';
    var userinfoPath = config.userinfoPath || '/oauth/userinfo';
    var revokePath = config.revokePath || '/oauth/revoke';
    var KEY_ACCESS_TOKEN = (config.storageKeyPrefix || '') + 'auth_access_token';
    var KEY_REFRESH_TOKEN = (config.storageKeyPrefix || '') + 'auth_refresh_token';
    var KEY_EXPIRES_AT = (config.storageKeyPrefix || '') + 'auth_expires_at';
    var KEY_CODE_VERIFIER = (config.storageKeyPrefix || '') + 'auth_code_verifier';
    var KEY_STATE = (config.storageKeyPrefix || '') + 'auth_state';
    var KEY_LOGIN_TS = (config.storageKeyPrefix || '') + 'auth_login_ts';
    function getStorage() {
        if (configuredStorage) {
            return configuredStorage;
        }
        if (typeof localStorage === 'undefined') {
            throw new Error('No storage available: pass config.storage outside the browser');
        }
        return localStorage;
    }
    function getRedirectUri() {
        if (configuredRedirectUri) {
            return configuredRedirectUri;
        }
        if (typeof window === 'undefined' || !window.location) {
            throw new Error('No redirectUri configured and window.location is unavailable');
        }
        return window.location.origin + '/auth/callback';
    }
    function navigate(url) {
        if (typeof window === 'undefined' || !window.location) {
            throw new Error('This operation requires a browser environment');
        }
        window.location.href = url;
    }
    function getAccessToken() {
        return getStorage().getItem(KEY_ACCESS_TOKEN);
    }
    function getRefreshToken() {
        return getStorage().getItem(KEY_REFRESH_TOKEN);
    }
    function getExpiresAt() {
        return parseInt(getStorage().getItem(KEY_EXPIRES_AT) || '0', 10);
    }
    function storeTokens(accessToken, refreshToken, expiresIn) {
        var storage = getStorage();
        storage.setItem(KEY_ACCESS_TOKEN, accessToken);
        if (refreshToken) {
            storage.setItem(KEY_REFRESH_TOKEN, refreshToken);
        }
        else {
            storage.removeItem(KEY_REFRESH_TOKEN);
        }
        storage.setItem(KEY_EXPIRES_AT, String(Date.now() + expiresIn * 1000));
    }
    function clearTokens() {
        var storage = getStorage();
        storage.removeItem(KEY_ACCESS_TOKEN);
        storage.removeItem(KEY_REFRESH_TOKEN);
        storage.removeItem(KEY_EXPIRES_AT);
    }
    function isAuthenticated() {
        var token = getAccessToken();
        if (!token)
            return false;
        return Date.now() < getExpiresAt() - EXPIRY_MARGIN_MS;
    }
    function login() {
        return __awaiter(this, void 0, void 0, function () {
            var verifier, challenge, state, storage, params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        verifier = (0, pkce_1.generateCodeVerifier)();
                        return [4 /*yield*/, (0, pkce_1.generateCodeChallenge)(verifier)];
                    case 1:
                        challenge = _a.sent();
                        state = (0, pkce_1.generateState)();
                        storage = getStorage();
                        storage.setItem(KEY_CODE_VERIFIER, verifier);
                        storage.setItem(KEY_STATE, state);
                        storage.setItem(KEY_LOGIN_TS, String(Date.now()));
                        params = new URLSearchParams({
                            response_type: 'code',
                            client_id: clientId,
                            redirect_uri: getRedirectUri(),
                            scope: scope,
                            state: state,
                            code_challenge: challenge,
                            code_challenge_method: 'S256',
                        });
                        navigate(authServerUrl + authorizePath + '?' + params.toString());
                        return [2 /*return*/];
                }
            });
        });
    }
    function handleCallback(code, state) {
        return __awaiter(this, void 0, void 0, function () {
            var storage, storedState, verifier, loginTs, body, response, text, data;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        storage = getStorage();
                        storedState = storage.getItem(KEY_STATE);
                        verifier = storage.getItem(KEY_CODE_VERIFIER);
                        loginTs = parseInt(storage.getItem(KEY_LOGIN_TS) || '0', 10);
                        storage.removeItem(KEY_STATE);
                        storage.removeItem(KEY_CODE_VERIFIER);
                        storage.removeItem(KEY_LOGIN_TS);
                        if (Date.now() - loginTs > loginAttemptTtlMs) {
                            throw new Error('Login attempt expired — please try again');
                        }
                        if (!storedState || state !== storedState) {
                            throw new Error('OAuth state mismatch — possible CSRF attack');
                        }
                        if (!verifier) {
                            throw new Error('No code verifier found — cannot complete token exchange');
                        }
                        body = new URLSearchParams({
                            grant_type: 'authorization_code',
                            code: code,
                            redirect_uri: getRedirectUri(),
                            client_id: clientId,
                            code_verifier: verifier,
                        });
                        return [4 /*yield*/, fetch(authServerUrl + tokenPath, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                                body: body.toString(),
                            })];
                    case 1:
                        response = _a.sent();
                        if (!!response.ok) return [3 /*break*/, 3];
                        return [4 /*yield*/, response.text()];
                    case 2:
                        text = _a.sent();
                        throw new Error('Token exchange failed (' + response.status + '): ' + text);
                    case 3: return [4 /*yield*/, response.json()];
                    case 4:
                        data = (_a.sent());
                        storeTokens(data.access_token, data.refresh_token, data.expires_in);
                        return [2 /*return*/, postLoginPath];
                }
            });
        });
    }
    var refreshPromise = null;
    function refreshAccessToken() {
        var _this = this;
        if (refreshPromise)
            return refreshPromise;
        refreshPromise = (function () { return __awaiter(_this, void 0, void 0, function () {
            var refreshToken, body, response, data, e_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        refreshToken = getRefreshToken();
                        if (!refreshToken)
                            return [2 /*return*/, false];
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 4, 5, 6]);
                        body = new URLSearchParams({
                            grant_type: 'refresh_token',
                            refresh_token: refreshToken,
                            client_id: clientId,
                        });
                        return [4 /*yield*/, fetch(authServerUrl + tokenPath, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                                body: body.toString(),
                            })];
                    case 2:
                        response = _a.sent();
                        if (!response.ok) {
                            clearTokens();
                            return [2 /*return*/, false];
                        }
                        return [4 /*yield*/, response.json()];
                    case 3:
                        data = (_a.sent());
                        storeTokens(data.access_token, data.refresh_token, data.expires_in);
                        return [2 /*return*/, true];
                    case 4:
                        e_1 = _a.sent();
                        clearTokens();
                        return [2 /*return*/, false];
                    case 5:
                        refreshPromise = null;
                        return [7 /*endfinally*/];
                    case 6: return [2 /*return*/];
                }
            });
        }); })();
        return refreshPromise;
    }
    function getValidAccessToken() {
        return __awaiter(this, void 0, void 0, function () {
            var refreshed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (isAuthenticated())
                            return [2 /*return*/, getAccessToken()];
                        return [4 /*yield*/, refreshAccessToken()];
                    case 1:
                        refreshed = _a.sent();
                        if (refreshed)
                            return [2 /*return*/, getAccessToken()];
                        return [2 /*return*/, null];
                }
            });
        });
    }
    function getUserInfo(accessToken) {
        return __awaiter(this, void 0, void 0, function () {
            var token, response, text;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        token = typeof accessToken === 'string' && accessToken.length > 0 ? accessToken : getAccessToken();
                        if (!token) {
                            throw new Error('No access token available');
                        }
                        return [4 /*yield*/, fetch(authServerUrl + userinfoPath, {
                                headers: { Authorization: 'Bearer ' + token },
                            })];
                    case 1:
                        response = _a.sent();
                        if (!!response.ok) return [3 /*break*/, 3];
                        return [4 /*yield*/, response.text()];
                    case 2:
                        text = _a.sent();
                        throw new Error('User info request failed (' + response.status + '): ' + text);
                    case 3: return [4 /*yield*/, response.json()];
                    case 4: return [2 /*return*/, (_a.sent())];
                }
            });
        });
    }
    function revoke(token) {
        return __awaiter(this, void 0, void 0, function () {
            var stored, target, body, response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        stored = getRefreshToken();
                        target = typeof token === 'string' && token.length > 0 ? token : stored;
                        if (!target)
                            return [2 /*return*/, false];
                        body = new URLSearchParams({
                            token: target,
                            client_id: clientId,
                        });
                        return [4 /*yield*/, fetch(authServerUrl + revokePath, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                                body: body.toString(),
                            })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, response.ok];
                }
            });
        });
    }
    function logout(redirectUri) {
        clearTokens();
        var fallback = typeof window !== 'undefined' && window.location ? window.location.origin : '';
        var target = typeof redirectUri === 'string' && redirectUri.length > 0 ? redirectUri : fallback;
        var params = new URLSearchParams({ redirect_uri: target });
        navigate(authServerUrl + logoutPath + '?' + params.toString());
    }
    return {
        login: login,
        handleCallback: handleCallback,
        isAuthenticated: isAuthenticated,
        getAccessToken: getAccessToken,
        refreshAccessToken: refreshAccessToken,
        getValidAccessToken: getValidAccessToken,
        getUserInfo: getUserInfo,
        revoke: revoke,
        logout: logout,
    };
}
