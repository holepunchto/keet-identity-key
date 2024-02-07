const test = require('brittle')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const IdentityKey = require('../')

test('basic', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const { identityPublicKey } = IdentityKey.from({ mnemonic })

  const proof = IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, publicKey)
  t.alike(auth && auth.identityPublicKey, identityPublicKey)
})

test('basic - timestamp fail', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null, { timestamp: Date.now() + 1 })

  t.alike(auth, null)
})

test('basic - root fail', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null, { identityPublicKey: publicKey })

  t.alike(auth, null)
})

test('basic - device authenticates another device', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = crypto.keyPair()
  const device2 = crypto.keyPair()

  const { identityPublicKey } = IdentityKey.from({ mnemonic })

  const proof1 = IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attest(device2.publicKey, device1, proof1)

  const auth = IdentityKey.verify(proof2, null)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, device2.publicKey)
  t.alike(auth && auth.identityPublicKey, identityPublicKey)
})

test('basic - device attests data', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = crypto.keyPair()
  const attestedData = b4a.from('attested data')

  const { identityPublicKey } = IdentityKey.from({ mnemonic })

  const proof1 = IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attestData(attestedData, device1, proof1)

  const auth = IdentityKey.verify(proof2, attestedData)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, device1.publicKey)
  t.alike(auth && auth.identityPublicKey, identityPublicKey)
})

test('basic - attested data fail', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = crypto.keyPair()
  const attestedData = b4a.from('attested data')

  const proof1 = IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attestData(attestedData, device1, proof1)

  const auth = IdentityKey.verify(proof2, b4a.from('not attested data'))

  t.alike(auth, null)
})

test('basic - root attests data', function (t) {
  const root = crypto.keyPair()
  const attestedData = b4a.from('attested data')

  const proof = IdentityKey.attestData(attestedData, root)
  const auth = IdentityKey.verify(proof, attestedData, { identityPublicKey: root.publicKey })

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, root.publicKey)
  t.alike(auth && auth.identityPublicKey, root.publicKey)
})
