import { generateCodeChallenge, generateCodeVerifier, generateState } from './pkce'

export interface TokenStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export interface AuthClientConfig {
  authServerUrl: string
  clientId: string
  redirectUri?: string
  scope?: string
  storageKeyPrefix?: string
  storage?: TokenStorage
  loginAttemptTtlMs?: number
  postLoginPath?: string
  authorizePath?: string
  tokenPath?: string
  logoutPath?: string
  userinfoPath?: string
  revokePath?: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  refresh_token?: string
  scope?: string
  id_token?: string
}

export interface UserInfo {
  sub: string
  user_id?: number
  email?: string
  email_verified?: boolean
  name?: string
  roles?: string[]
}

export interface AuthClient {
  login(): Promise<void>
  handleCallback(code: string, state: string): Promise<string>
  isAuthenticated(): boolean
  getAccessToken(): string | null
  refreshAccessToken(): Promise<boolean>
  getValidAccessToken(): Promise<string | null>
  getUserInfo(accessToken?: string): Promise<UserInfo>
  revoke(token?: string): Promise<boolean>
  logout(redirectUri?: string): void
}

const DEFAULT_SCOPE = 'openid profile email'
const DEFAULT_LOGIN_ATTEMPT_TTL_MS = 10 * 60 * 1000
const DEFAULT_POST_LOGIN_PATH = '/'
const EXPIRY_MARGIN_MS = 60 * 1000

function stripTrailingSlash(url: string): string {
  return url.length > 0 && url.charAt(url.length - 1) === '/' ? url.slice(0, -1) : url
}

export function createAuthClient(config: AuthClientConfig): AuthClient {
  if (!config) {
    throw new Error('config is required')
  }
  if (!config.authServerUrl) {
    throw new Error('authServerUrl is required')
  }
  if (!config.clientId) {
    throw new Error('clientId is required')
  }

  const authServerUrl = stripTrailingSlash(config.authServerUrl)
  const clientId = config.clientId
  const scope = config.scope || DEFAULT_SCOPE
  const configuredRedirectUri = config.redirectUri
  const configuredStorage = config.storage
  const loginAttemptTtlMs = config.loginAttemptTtlMs || DEFAULT_LOGIN_ATTEMPT_TTL_MS
  const postLoginPath = config.postLoginPath || DEFAULT_POST_LOGIN_PATH
  const authorizePath = config.authorizePath || '/oauth/authorize'
  const tokenPath = config.tokenPath || '/oauth/token'
  const logoutPath = config.logoutPath || '/api/auth/logout'
  const userinfoPath = config.userinfoPath || '/oauth/userinfo'
  const revokePath = config.revokePath || '/oauth/revoke'

  const KEY_ACCESS_TOKEN = (config.storageKeyPrefix || '') + 'auth_access_token'
  const KEY_REFRESH_TOKEN = (config.storageKeyPrefix || '') + 'auth_refresh_token'
  const KEY_EXPIRES_AT = (config.storageKeyPrefix || '') + 'auth_expires_at'
  const KEY_CODE_VERIFIER = (config.storageKeyPrefix || '') + 'auth_code_verifier'
  const KEY_STATE = (config.storageKeyPrefix || '') + 'auth_state'
  const KEY_LOGIN_TS = (config.storageKeyPrefix || '') + 'auth_login_ts'

  function getStorage(): TokenStorage {
    if (configuredStorage) {
      return configuredStorage
    }
    if (typeof localStorage === 'undefined') {
      throw new Error('No storage available: pass config.storage outside the browser')
    }
    return localStorage
  }

  function getRedirectUri(): string {
    if (configuredRedirectUri) {
      return configuredRedirectUri
    }
    if (typeof window === 'undefined' || !window.location) {
      throw new Error('No redirectUri configured and window.location is unavailable')
    }
    return window.location.origin + '/auth/callback'
  }

  function navigate(url: string): void {
    if (typeof window === 'undefined' || !window.location) {
      throw new Error('This operation requires a browser environment')
    }
    window.location.href = url
  }

  function getAccessToken(): string | null {
    return getStorage().getItem(KEY_ACCESS_TOKEN)
  }

  function getRefreshToken(): string | null {
    return getStorage().getItem(KEY_REFRESH_TOKEN)
  }

  function getExpiresAt(): number {
    return parseInt(getStorage().getItem(KEY_EXPIRES_AT) || '0', 10)
  }

  function storeTokens(accessToken: string, refreshToken: string | undefined, expiresIn: number): void {
    const storage = getStorage()
    storage.setItem(KEY_ACCESS_TOKEN, accessToken)
    if (refreshToken) {
      storage.setItem(KEY_REFRESH_TOKEN, refreshToken)
    } else {
      storage.removeItem(KEY_REFRESH_TOKEN)
    }
    storage.setItem(KEY_EXPIRES_AT, String(Date.now() + expiresIn * 1000))
  }

  function clearTokens(): void {
    const storage = getStorage()
    storage.removeItem(KEY_ACCESS_TOKEN)
    storage.removeItem(KEY_REFRESH_TOKEN)
    storage.removeItem(KEY_EXPIRES_AT)
  }

  function isAuthenticated(): boolean {
    const token = getAccessToken()
    if (!token) return false
    return Date.now() < getExpiresAt() - EXPIRY_MARGIN_MS
  }

  async function login(): Promise<void> {
    const verifier = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    const state = generateState()

    const storage = getStorage()
    storage.setItem(KEY_CODE_VERIFIER, verifier)
    storage.setItem(KEY_STATE, state)
    storage.setItem(KEY_LOGIN_TS, String(Date.now()))

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: getRedirectUri(),
      scope: scope,
      state: state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })

    navigate(authServerUrl + authorizePath + '?' + params.toString())
  }

  async function handleCallback(code: string, state: string): Promise<string> {
    const storage = getStorage()
    const storedState = storage.getItem(KEY_STATE)
    const verifier = storage.getItem(KEY_CODE_VERIFIER)
    const loginTs = parseInt(storage.getItem(KEY_LOGIN_TS) || '0', 10)

    storage.removeItem(KEY_STATE)
    storage.removeItem(KEY_CODE_VERIFIER)
    storage.removeItem(KEY_LOGIN_TS)

    if (Date.now() - loginTs > loginAttemptTtlMs) {
      throw new Error('Login attempt expired — please try again')
    }

    if (!storedState || state !== storedState) {
      throw new Error('OAuth state mismatch — possible CSRF attack')
    }

    if (!verifier) {
      throw new Error('No code verifier found — cannot complete token exchange')
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: getRedirectUri(),
      client_id: clientId,
      code_verifier: verifier,
    })

    const response = await fetch(authServerUrl + tokenPath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })

    if (!response.ok) {
      const text = await response.text()
      throw new Error('Token exchange failed (' + response.status + '): ' + text)
    }

    const data = (await response.json()) as TokenResponse
    storeTokens(data.access_token, data.refresh_token, data.expires_in)

    return postLoginPath
  }

  let refreshPromise: Promise<boolean> | null = null

  function refreshAccessToken(): Promise<boolean> {
    if (refreshPromise) return refreshPromise

    refreshPromise = (async () => {
      const refreshToken = getRefreshToken()
      if (!refreshToken) return false

      try {
        const body = new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: clientId,
        })

        const response = await fetch(authServerUrl + tokenPath, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: body.toString(),
        })

        if (!response.ok) {
          clearTokens()
          return false
        }

        const data = (await response.json()) as TokenResponse
        storeTokens(data.access_token, data.refresh_token, data.expires_in)
        return true
      } catch (e) {
        clearTokens()
        return false
      } finally {
        refreshPromise = null
      }
    })()

    return refreshPromise
  }

  async function getValidAccessToken(): Promise<string | null> {
    if (isAuthenticated()) return getAccessToken()
    const refreshed = await refreshAccessToken()
    if (refreshed) return getAccessToken()
    return null
  }

  async function getUserInfo(accessToken?: string): Promise<UserInfo> {
    const token = accessToken || getAccessToken()
    if (!token) {
      throw new Error('No access token available')
    }

    const response = await fetch(authServerUrl + userinfoPath, {
      headers: { Authorization: 'Bearer ' + token },
    })

    if (!response.ok) {
      const text = await response.text()
      throw new Error('User info request failed (' + response.status + '): ' + text)
    }

    return (await response.json()) as UserInfo
  }

  async function revoke(token?: string): Promise<boolean> {
    const target = token || getRefreshToken()
    if (!target) return false

    const body = new URLSearchParams({
      token: target,
      client_id: clientId,
    })

    const response = await fetch(authServerUrl + revokePath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })

    return response.ok
  }

  function logout(redirectUri?: string): void {
    clearTokens()
    const target = redirectUri || (typeof window !== 'undefined' && window.location ? window.location.origin : '')
    const params = new URLSearchParams({ redirect_uri: target })
    navigate(authServerUrl + logoutPath + '?' + params.toString())
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
  }
}
