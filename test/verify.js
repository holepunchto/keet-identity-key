const { execFileSync } = require('child_process')
const path = require('path')
const test = require('brittle')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const IdentityKey = require('../')
const verify = require('../lib/verify')

test('verify - same result as IdentityKey.verify', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()
  const device = crypto.keyPair()
  const attestedData = b4a.from('attested data')

  const id = await IdentityKey.from({ mnemonic })
  const bootstrap = await IdentityKey.bootstrap({ mnemonic }, device.publicKey)
  const proof = IdentityKey.attestData(attestedData, device, bootstrap)

  const auth = verify(proof, attestedData)

  t.alike(auth, IdentityKey.verify(proof, attestedData))
  t.alike(auth.devicePublicKey, device.publicKey)
  t.alike(auth.identityPublicKey, id.identityPublicKey)
})

test('verify - rejects a proof for other data', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()
  const device = crypto.keyPair()

  const bootstrap = await IdentityKey.bootstrap({ mnemonic }, device.publicKey)
  const proof = IdentityKey.attestData(b4a.from('attested data'), device, bootstrap)

  t.is(verify(proof, b4a.from('other data')), null)
})

test('verify - does not load the keychain or the word lists', function (t) {
  const script = `
    require('./lib/verify')
    const loaded = Object.keys(require.cache).filter(function (file) {
      return file.includes('bip39-mnemonic') || file.endsWith('keychain.js')
    })
    process.stdout.write(JSON.stringify(loaded))
  `
  const out = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..')
  })

  t.alike(JSON.parse(out.toString()), [])
})
