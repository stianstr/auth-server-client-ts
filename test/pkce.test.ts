import { eq, test } from './harness'
import { base64urlEncode, generateCodeChallenge } from '../src/pkce'

test('base64urlEncode produces unpadded URL-safe output', () => {
  const bytes = new Uint8Array([
    0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca,
    0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23, 0xdc, 0x4d,
    0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72,
    0xb9, 0x80, 0x77, 0x85, 0xaf, 0xee, 0x48, 0xbb,
  ])
  eq(base64urlEncode(bytes.buffer), 'ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs')
})

test('generateCodeChallenge matches the RFC 7636 appendix B vector', async () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
  const challenge = await generateCodeChallenge(verifier)
  eq(challenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
})
