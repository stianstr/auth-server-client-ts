export interface TokenStorage {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
}
export interface AuthClientConfig {
    authServerUrl: string;
    clientId: string;
    redirectUri?: string;
    scope?: string;
    storageKeyPrefix?: string;
    storage?: TokenStorage;
    loginAttemptTtlMs?: number;
    postLoginPath?: string;
    authorizePath?: string;
    tokenPath?: string;
    logoutPath?: string;
    userinfoPath?: string;
    revokePath?: string;
}
export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
}
export interface UserInfo {
    sub: string;
    user_id?: number;
    email?: string;
    email_verified?: boolean;
    name?: string;
    roles?: string[];
}
export interface AuthClient {
    login(): Promise<void>;
    handleCallback(code: string, state: string): Promise<string>;
    isAuthenticated(): boolean;
    getAccessToken(): string | null;
    refreshAccessToken(): Promise<boolean>;
    getValidAccessToken(): Promise<string | null>;
    getUserInfo(accessToken?: string): Promise<UserInfo>;
    revoke(token?: string): Promise<boolean>;
    logout(redirectUri?: string): void;
}
export declare function createAuthClient(config: AuthClientConfig): AuthClient;
