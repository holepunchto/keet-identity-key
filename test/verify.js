const { spawnSync } = require('child_process')
const test = require('brittle')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const IdentityKey = require('../')
const verify = require('../lib/verify')

test('verify - device attests data', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()
  const device = crypto.keyPair()
  const attestedData = b4a.from('attested data')

  const id = await IdentityKey.from({ mnemonic })
  const bootstrap = await IdentityKey.bootstrap({ mnemonic }, device.publicKey)
  const proof = IdentityKey.attestData(attestedData, device, bootstrap)

  const auth = verify(proof, attestedData)

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
    require(${JSON.stringify(require.resolve('../lib/verify'))})
    const loaded = Object.keys(require.cache).filter(function (file) {
      return file.includes('bip39-mnemonic') || file.endsWith('keychain.js')
    })
    console.log(JSON.stringify(loaded))
  `
  const runtime = global.Bare ? global.Bare.argv[0] : process.execPath
  const { stdout } = spawnSync(runtime, ['-e', script], {
    stdio: ['ignore', 'pipe', 'inherit']
  })

  t.alike(JSON.parse(stdout.toString()), [])
})
