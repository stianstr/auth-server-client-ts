export type TestFn = () => void | Promise<void>

interface RegisteredTest {
  name: string
  fn: TestFn
}

const tests: RegisteredTest[] = []

export function test(name: string, fn: TestFn): void {
  tests.push({ name: name, fn: fn })
}

export function eq(actual: unknown, expected: unknown, message?: string): void {
  const label = message || 'eq'
  if (actual !== expected) {
    throw new Error(label + ': expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual))
  }
}

export function ok(value: unknown, message?: string): void {
  if (!value) {
    throw new Error(message || 'ok: expected truthy, got ' + JSON.stringify(value))
  }
}

export async function run(): Promise<void> {
  let passed = 0
  const failures: string[] = []
  for (const t of tests) {
    try {
      await t.fn()
      passed++
    } catch (e) {
      failures.push(t.name + ': ' + (e instanceof Error ? e.message : String(e)))
    }
  }
  for (const f of failures) {
    console.log('FAIL ' + f)
  }
  console.log(passed + ' passed, ' + failures.length + ' failed, ' + tests.length + ' total')
  if (failures.length > 0) {
    process.exitCode = 1
  }
}
