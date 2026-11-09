import * as nodeCrypto from 'crypto'
import { TokenStorage } from '../src/client'

export class MemoryStorage implements TokenStorage {
  private map = new Map<string, string>()

  getItem(key: string): string | null {
    const value = this.map.get(key)
    return value === undefined ? null : value
  }

  setItem(key: string, value: string): void {
    this.map.set(key, value)
  }

  removeItem(key: string): void {
    this.map.delete(key)
  }

  clear(): void {
    this.map.clear()
  }
}

export const fakeWindow = {
  location: {
    origin: 'https://app.example.com',
    href: 'about:blank',
  },
}

export type RecordedRequest = {
  url: string
  method: string
  headers: Record<string, string>
  body: string | null
}

export type MockResponse = {
  ok: boolean
  status: number
  body: string
}

export const recorded: RecordedRequest[] = []
let nextResponse: MockResponse | null = null
let responseQueue: MockResponse[] = []

export function respondWith(response: MockResponse): void {
  nextResponse = response
  responseQueue = []
}

export function respondWithQueue(responses: MockResponse[]): void {
  responseQueue = responses.slice()
  nextResponse = null
}

function mockFetch(url: string, init?: RequestInit): Promise<unknown> {
  recorded.push({
    url: url,
    method: init && init.method ? init.method : 'GET',
    headers: (init && (init.headers as Record<string, string>)) || {},
    body: init && init.body ? String(init.body) : null,
  })
  const response = responseQueue.length > 0 ? responseQueue.shift() : nextResponse
  if (!response) {
    return Promise.reject(new Error('Unexpected fetch in test: ' + url))
  }
  return Promise.resolve({
    ok: response.ok,
    status: response.status,
    text: () => Promise.resolve(response.body),
    json: () => Promise.resolve(JSON.parse(response.body)),
  })
}

function mockGetRandomValues(array: Uint8Array): Uint8Array {
  for (let i = 0; i < array.length; i++) {
    array[i] = (i * 7 + 11) % 256
  }
  return array
}

export function installBrowserEnv(storage: MemoryStorage): void {
  const g = globalThis as Record<string, unknown>
  g.localStorage = storage
  g.window = fakeWindow
  g.fetch = mockFetch
  const webcrypto = (nodeCrypto as unknown as { webcrypto: unknown }).webcrypto
  Object.defineProperty(globalThis, 'crypto', {
    value: {
      getRandomValues: mockGetRandomValues,
      subtle: (webcrypto as { subtle: unknown }).subtle,
    },
    configurable: true,
    writable: true,
    enumerable: true,
  })
  recorded.length = 0
  nextResponse = null
  responseQueue = []
  fakeWindow.location.href = 'about:blank'
}

export function lastRequest(): RecordedRequest {
  if (recorded.length === 0) {
    throw new Error('lastRequest: no request was recorded')
  }
  return recorded[recorded.length - 1]
}

export function parseQuery(url: string): Record<string, string> {
  const query = url.slice(url.indexOf('?') + 1)
  const result: Record<string, string> = {}
  const params = new URLSearchParams(query)
  params.forEach((value: string, key: string) => {
    result[key] = value
  })
  return result
}
