import { eq, ok, test } from './harness'
import { generateCodeChallenge } from '../src/pkce'
import { AuthClientConfig, TokenResponse, UserInfo, createAuthClient } from '../src/client'
import {
  MemoryStorage,
  fakeWindow,
  installBrowserEnv,
  lastRequest,
  parseQuery,
  recorded,
  respondWith,
  respondWithQueue,
} from './env'

const AUTH_URL = 'https://auth.example.com'

function newClient(overrides?: Partial<AuthClientConfig>) {
  const storage = new MemoryStorage()
  installBrowserEnv(storage)
  const client = createAuthClient(
    Object.assign(
      { authServerUrl: AUTH_URL, clientId: 'my-client' },
      overrides || {}
    )
  )
  return { client: client, storage: storage }
}

function tokenResponse(refreshToken?: string): string {
  const body: TokenResponse = {
    access_token: 'at-xyz',
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: refreshToken === undefined ? 'rt-abc' : refreshToken,
    scope: 'openid profile email',
  }
  return JSON.stringify(body)
}

test('createAuthClient requires authServerUrl and clientId', () => {
  let threw = ''
  try {
    createAuthClient({ authServerUrl: '', clientId: 'x' })
  } catch (e) {
    threw = (e as Error).message
  }
  ok(threw.indexOf('authServerUrl') >= 0, 'authServerUrl required')

  threw = ''
  try {
    createAuthClient({ authServerUrl: 'https://x', clientId: '' })
  } catch (e) {
    threw = (e as Error).message
  }
  ok(threw.indexOf('clientId') >= 0, 'clientId required')
})

test('trailing slash on authServerUrl is normalized', async () => {
  const { client, storage } = newClient({ authServerUrl: AUTH_URL + '/' })
  primeLogin(storage)
  respondWith({ ok: true, status: 200, body: tokenResponse() })
  const result = await client.handleCallback('c', 'st-123')
  eq(result, '/')
  eq(lastRequest().url, AUTH_URL + '/oauth/token')
})

test('login stores verifier/state/timestamp and redirects to authorize', async () => {
  const { client, storage } = newClient()
  await client.login()

  ok(storage.getItem('auth_code_verifier'), 'verifier stored')
  ok(storage.getItem('auth_state'), 'state stored')
  ok(storage.getItem('auth_login_ts'), 'timestamp stored')

  const url = fakeWindow.location.href
  ok(url.indexOf(AUTH_URL + '/oauth/authorize?') === 0, 'redirects to authorize: ' + url)
  const params = parseQuery(url)
  eq(params['response_type'], 'code')
  eq(params['client_id'], 'my-client')
  eq(params['redirect_uri'], 'https://app.example.com/auth/callback')
  eq(params['scope'], 'openid profile email')
  eq(params['code_challenge_method'], 'S256')
  eq(params['code_challenge'], await generateCodeChallenge(storage.getItem('auth_code_verifier') || ''))
  eq(params['state'], storage.getItem('auth_state'))
})

test('custom redirectUri and scope are honored', async () => {
  const { client } = newClient({ redirectUri: 'https://other.example.com/cb', scope: 'openid' })
  await client.login()
  const params = parseQuery(fakeWindow.location.href)
  eq(params['redirect_uri'], 'https://other.example.com/cb')
  eq(params['scope'], 'openid')
})

function primeLogin(storage: MemoryStorage): { code: string; state: string } {
  storage.setItem('auth_state', 'st-123')
  storage.setItem('auth_code_verifier', 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
  storage.setItem('auth_login_ts', String(Date.now()))
  return { code: 'auth-code-1', state: 'st-123' }
}

test('handleCallback exchanges the code and stores tokens', async () => {
  const { client, storage } = newClient()
  const { code, state } = primeLogin(storage)
  respondWith({ ok: true, status: 200, body: tokenResponse() })

  const result = await client.handleCallback(code, state)
  eq(result, '/')

  const request = lastRequest()
  eq(request.url, AUTH_URL + '/oauth/token')
  eq(request.method, 'POST')
  eq(request.headers['Content-Type'], 'application/x-www-form-urlencoded')
  const form = parseQuery('?' + (request.body || ''))
  eq(form['grant_type'], 'authorization_code')
  eq(form['code'], 'auth-code-1')
  eq(form['client_id'], 'my-client')
  eq(form['code_verifier'], 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
  eq(form['redirect_uri'], 'https://app.example.com/auth/callback')

  eq(storage.getItem('auth_access_token'), 'at-xyz')
  eq(storage.getItem('auth_refresh_token'), 'rt-abc')
  eq(storage.getItem('auth_state'), null, 'flow state cleared')
  eq(storage.getItem('auth_code_verifier'), null, 'verifier cleared')
  eq(storage.getItem('auth_login_ts'), null, 'timestamp cleared')
})

test('handleCallback rejects a state mismatch', async () => {
  const { client, storage } = newClient()
  primeLogin(storage)
  let message = ''
  try {
    await client.handleCallback('c', 'wrong-state')
  } catch (e) {
    message = (e as Error).message
  }
  ok(message.indexOf('state mismatch') >= 0, 'state mismatch thrown')
})

test('handleCallback rejects a stale login attempt', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_state', 'st-123')
  storage.setItem('auth_code_verifier', 'v')
  storage.setItem('auth_login_ts', String(Date.now() - 11 * 60 * 1000))
  let message = ''
  try {
    await client.handleCallback('c', 'st-123')
  } catch (e) {
    message = (e as Error).message
  }
  ok(message.indexOf('expired') >= 0, 'staleness thrown')
})

test('handleCallback honors a custom loginAttemptTtlMs', async () => {
  const { client, storage } = newClient({ loginAttemptTtlMs: 60 * 1000 })
  primeLogin(storage)
  storage.setItem('auth_login_ts', String(Date.now() - 5 * 60 * 1000))
  let message = ''
  try {
    await client.handleCallback('c', 'st-123')
  } catch (e) {
    message = (e as Error).message
  }
  ok(message.indexOf('expired') >= 0, 'custom ttl applied')
})

test('handleCallback rejects a missing verifier', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_state', 'st-123')
  storage.setItem('auth_login_ts', String(Date.now()))
  let message = ''
  try {
    await client.handleCallback('c', 'st-123')
  } catch (e) {
    message = (e as Error).message
  }
  ok(message.indexOf('code verifier') >= 0, 'missing verifier thrown')
})

test('handleCallback surfaces token-endpoint errors', async () => {
  const { client, storage } = newClient()
  primeLogin(storage)
  respondWith({ ok: false, status: 400, body: '{"error":"invalid_grant"}' })
  let message = ''
  try {
    await client.handleCallback('c', 'st-123')
  } catch (e) {
    message = (e as Error).message
  }
  ok(message.indexOf('400') >= 0 && message.indexOf('invalid_grant') >= 0, 'error surfaced')
})

test('handleCallback tolerates a response without a refresh token', async () => {
  const { client, storage } = newClient()
  primeLogin(storage)
  const body = JSON.stringify({
    access_token: 'at-xyz',
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'openid',
  })
  respondWith({ ok: true, status: 200, body: body })
  await client.handleCallback('c', 'st-123')
  eq(storage.getItem('auth_access_token'), 'at-xyz')
  eq(storage.getItem('auth_refresh_token'), null, 'no refresh token stored')
})

test('isAuthenticated uses a 60s safety margin', () => {
  const { client, storage } = newClient()
  eq(client.isAuthenticated(), false)

  storage.setItem('auth_access_token', 'at')
  storage.setItem('auth_expires_at', String(Date.now() + 30 * 1000))
  eq(client.isAuthenticated(), false, '30s left counts as expired')

  storage.setItem('auth_expires_at', String(Date.now() + 120 * 1000))
  eq(client.isAuthenticated(), true, '120s left is valid')
})

test('refreshAccessToken stores the new pair', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_refresh_token', 'rt-old')
  respondWith({ ok: true, status: 200, body: tokenResponse('rt-new') })

  eq(await client.refreshAccessToken(), true)
  const request = lastRequest()
  eq(request.method, 'POST')
  const form = parseQuery('?' + (request.body || ''))
  eq(form['grant_type'], 'refresh_token')
  eq(form['refresh_token'], 'rt-old')
  eq(form['client_id'], 'my-client')
  eq(storage.getItem('auth_refresh_token'), 'rt-new')
})

test('refreshAccessToken clears tokens when the server refuses', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_access_token', 'at')
  storage.setItem('auth_refresh_token', 'rt-old')
  storage.setItem('auth_expires_at', String(Date.now() + 1000))
  respondWith({ ok: false, status: 400, body: '{"error":"invalid_grant"}' })

  eq(await client.refreshAccessToken(), false)
  eq(storage.getItem('auth_access_token'), null, 'cleared')
  eq(storage.getItem('auth_refresh_token'), null, 'cleared')
})

test('refreshAccessToken returns false without a refresh token', async () => {
  const { client } = newClient()
  eq(await client.refreshAccessToken(), false)
})

test('concurrent refreshes are deduplicated into one request', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_refresh_token', 'rt-old')
  respondWithQueue([{ ok: true, status: 200, body: tokenResponse('rt-new') }])

  const first = client.refreshAccessToken()
  const second = client.refreshAccessToken()
  eq(await first, true)
  eq(await second, true)
  eq(recorded.length, 1)
})

test('refresh failure mid-flight clears tokens', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_refresh_token', 'rt-old')
  const g = globalThis as Record<string, unknown>
  const originalFetch = g.fetch
  g.fetch = () => Promise.reject(new Error('network down'))
  try {
    eq(await client.refreshAccessToken(), false)
    eq(storage.getItem('auth_refresh_token'), null, 'cleared on network error')
  } finally {
    g.fetch = originalFetch
  }
})

test('getValidAccessToken returns the stored token when fresh', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_access_token', 'at-fresh')
  storage.setItem('auth_expires_at', String(Date.now() + 3600 * 1000))
  eq(await client.getValidAccessToken(), 'at-fresh')
})

test('getValidAccessToken refreshes an expired token', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_access_token', 'at-stale')
  storage.setItem('auth_refresh_token', 'rt-old')
  storage.setItem('auth_expires_at', String(Date.now() - 1000))
  respondWith({ ok: true, status: 200, body: tokenResponse('rt-new') })

  eq(await client.getValidAccessToken(), 'at-xyz')
})

test('getValidAccessToken returns null when refresh fails', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_access_token', 'at-stale')
  storage.setItem('auth_refresh_token', 'rt-old')
  storage.setItem('auth_expires_at', String(Date.now() - 1000))
  respondWith({ ok: false, status: 400, body: '{"error":"invalid_grant"}' })

  eq(await client.getValidAccessToken(), null)
})

const USERINFO_BODY: UserInfo = {
  sub: 'user@example.com',
  user_id: 7,
  email: 'user@example.com',
  email_verified: true,
  name: 'Example User',
  roles: ['admin'],
}

test('getUserInfo sends the stored token as Bearer and parses claims', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_access_token', 'at-xyz')
  respondWith({ ok: true, status: 200, body: JSON.stringify(USERINFO_BODY) })

  const info = await client.getUserInfo()
  eq(lastRequest().url, AUTH_URL + '/oauth/userinfo')
  eq(lastRequest().headers['Authorization'], 'Bearer at-xyz')
  eq(info.sub, 'user@example.com')
  eq(info.name, 'Example User')
})

test('getUserInfo accepts an explicit token', async () => {
  const { client } = newClient()
  respondWith({ ok: true, status: 200, body: JSON.stringify(USERINFO_BODY) })
  await client.getUserInfo('at-explicit')
  eq(lastRequest().headers['Authorization'], 'Bearer at-explicit')
})

test('getUserInfo throws without any token', async () => {
  const { client } = newClient()
  let message = ''
  try {
    await client.getUserInfo()
  } catch (e) {
    message = (e as Error).message
  }
  ok(message.indexOf('No access token') >= 0)
})

test('getUserInfo surfaces a 401', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_access_token', 'at-xyz')
  respondWith({ ok: false, status: 401, body: 'Unauthorized' })
  let message = ''
  try {
    await client.getUserInfo()
  } catch (e) {
    message = (e as Error).message
  }
  ok(message.indexOf('401') >= 0)
})

test('revoke posts the refresh token and client_id', async () => {
  const { client, storage } = newClient()
  storage.setItem('auth_refresh_token', 'rt-abc')
  respondWith({ ok: true, status: 200, body: '' })

  eq(await client.revoke(), true)
  const request = lastRequest()
  eq(request.url, AUTH_URL + '/oauth/revoke')
  eq(request.method, 'POST')
  const form = parseQuery('?' + (request.body || ''))
  eq(form['token'], 'rt-abc')
  eq(form['client_id'], 'my-client')
})

test('revoke accepts an explicit token', async () => {
  const { client } = newClient()
  respondWith({ ok: true, status: 200, body: '' })
  eq(await client.revoke('some-token'), true)
  eq(parseQuery('?' + (lastRequest().body || ''))['token'], 'some-token')
})

test('revoke returns false with no token to revoke', async () => {
  const { client } = newClient()
  eq(await client.revoke(), false)
})

test('revoke returns false on server error', async () => {
  const { client } = newClient()
  respondWith({ ok: false, status: 401, body: 'invalid_client' })
  eq(await client.revoke('tok'), false)
})

test('logout clears tokens and redirects to the logout endpoint', () => {
  const { client, storage } = newClient()
  storage.setItem('auth_access_token', 'at')
  storage.setItem('auth_refresh_token', 'rt')
  storage.setItem('auth_expires_at', '1')

  client.logout()
  eq(storage.getItem('auth_access_token'), null)
  eq(storage.getItem('auth_refresh_token'), null)
  eq(storage.getItem('auth_expires_at'), null)

  const url = fakeWindow.location.href
  ok(url.indexOf(AUTH_URL + '/api/auth/logout?') === 0, 'default logout path: ' + url)
  eq(parseQuery(url)['redirect_uri'], 'https://app.example.com')
})

test('logout honors a custom logoutPath and redirectUri', () => {
  const { client } = newClient({ logoutPath: '/auth/logout' })
  client.logout('https://elsewhere.example.com/bye')
  ok(fakeWindow.location.href.indexOf(AUTH_URL + '/auth/logout?') === 0)
  eq(parseQuery(fakeWindow.location.href)['redirect_uri'], 'https://elsewhere.example.com/bye')
})

test('storageKeyPrefix isolates two clients on one origin', () => {
  const storageA = new MemoryStorage()
  const storageB = new MemoryStorage()
  installBrowserEnv(storageA)

  const clientA = createAuthClient({ authServerUrl: AUTH_URL, clientId: 'a', storage: storageA })
  const clientB = createAuthClient({
    authServerUrl: AUTH_URL,
    clientId: 'b',
    storage: storageB,
    storageKeyPrefix: 'app_',
  })

  storageA.setItem('auth_access_token', 'token-a')
  storageB.setItem('app_auth_access_token', 'token-b')

  eq(clientA.getAccessToken(), 'token-a')
  eq(clientB.getAccessToken(), 'token-b')
})

test('an explicit storage implementation replaces localStorage', async () => {
  const storage = new MemoryStorage()
  installBrowserEnv(storage)
  const isolated = new MemoryStorage()
  const client = createAuthClient({
    authServerUrl: AUTH_URL,
    clientId: 'my-client',
    storage: isolated,
  })
  isolated.setItem('auth_state', 'st-1')
  isolated.setItem('auth_code_verifier', 'v')
  isolated.setItem('auth_login_ts', String(Date.now()))
  respondWith({ ok: true, status: 200, body: tokenResponse() })

  await client.handleCallback('c', 'st-1')
  eq(isolated.getItem('auth_access_token'), 'at-xyz')
  eq(storage.getItem('auth_access_token'), null, 'default storage untouched')
})

test('requesting localStorage storage outside a browser throws clearly', () => {
  const g = globalThis as Record<string, unknown>
  const savedLocalStorage = g.localStorage
  const savedWindow = g.window
  delete g.localStorage
  delete g.window
  try {
    const client = createAuthClient({ authServerUrl: AUTH_URL, clientId: 'my-client' })
    let message = ''
    try {
      client.getAccessToken()
    } catch (e) {
      message = (e as Error).message
    }
    ok(message.indexOf('config.storage') >= 0, 'actionable error: ' + message)
  } finally {
    g.localStorage = savedLocalStorage
    g.window = savedWindow
  }
})
