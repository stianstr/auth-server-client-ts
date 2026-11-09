import { run } from './harness'
import './pkce.test'
import './client.test'

run().catch((e) => {
  console.error(e)
  process.exitCode = 1
})
