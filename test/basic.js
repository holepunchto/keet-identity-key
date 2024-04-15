const test = require('brittle')
const crypto = require('hypercore-crypto')
const c = require('compact-encoding')
const b4a = require('b4a')

const IdentityKey = require('../')
const { ProofEncoding } = require('../lib/encoding')

test('basic', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const id = await IdentityKey.from({ mnemonic })

  const proof = await IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null)

  t.unlike(id.identityKeyPair, null)
  t.unlike(id.identityPublicKey, null)
  t.unlike(id.profileDiscoveryKeyPair, null)
  t.unlike(id.profileDiscoveryPublicKey, null)
  t.unlike(id.getProfileDiscoveryEncryptionKey(), null)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, publicKey)
  t.alike(auth && auth.identityPublicKey, id.identityPublicKey)
})

test('basic - epoch fail', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = await IdentityKey.bootstrap({ mnemonic }, publicKey)
  const receipt = c.encode(c.uint64, Date.now() + 1)

  const auth = IdentityKey.verify(proof, null, { receipt })

  t.alike(auth, null)
})

test('basic - root fail', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = await IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null, { expectedIdentity: b4a.alloc(32) })

  t.alike(auth, null)
})

test('basic - device fail', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = await IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null, { expectedDevice: b4a.alloc(32) })

  t.alike(auth, null)
})

test('basic - device authenticates another device', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = crypto.keyPair()
  const device2 = crypto.keyPair()

  const id = await IdentityKey.from({ mnemonic })

  const proof1 = await IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attestDevice(device2.publicKey, device1, proof1)

  const auth = IdentityKey.verify(proof2, null)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, device2.publicKey)
  t.alike(auth && auth.identityPublicKey, id.identityPublicKey)
})

test('basic - device attests data', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = crypto.keyPair()
  const attestedData = b4a.from('attested data')

  const id = await IdentityKey.from({ mnemonic })

  const proof1 = await IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attestData(attestedData, device1, proof1)

  const auth = IdentityKey.verify(proof2, attestedData)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, device1.publicKey)
  t.alike(auth && auth.identityPublicKey, id.identityPublicKey)
})

test('basic - attested data fail', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = crypto.keyPair()
  const attestedData = b4a.from('attested data')

  const proof1 = await IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attestData(attestedData, device1, proof1)

  const auth = IdentityKey.verify(proof2, b4a.from('not attested data'))

  t.alike(auth, null)
})

test('basic - root attests data', async function (t) {
  const root = crypto.keyPair()
  const attestedData = b4a.from('attested data')

  const proof = IdentityKey.attestData(attestedData, root)
  const auth = IdentityKey.verify(proof, attestedData, { identityPublicKey: root.publicKey })

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, root.publicKey)
  t.alike(auth && auth.identityPublicKey, root.publicKey)
})

test('basic - encryption keys', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const id = await IdentityKey.from({ mnemonic })

  const profile1 = crypto.keyPair()
  const profile2 = crypto.keyPair()

  const enc1 = id.getEncryptionKey(profile1.publicKey)
  const enc2 = id.getEncryptionKey(profile2.publicKey)

  t.unlike(enc1, null)
  t.unlike(enc2, null)
  t.unlike(enc1, enc2)

  t.unlike(enc1, id.getProfileDiscoveryEncryptionKey())
  t.unlike(enc2, id.getProfileDiscoveryEncryptionKey())

  const id2 = await IdentityKey.from({ mnemonic })

  const enc1a = id2.getEncryptionKey(profile1.publicKey)
  const enc2a = id2.getEncryptionKey(profile2.publicKey)

  t.alike(enc1, enc1a)
  t.alike(enc2, enc2a)
  t.alike(id.getProfileDiscoveryEncryptionKey(), id2.getProfileDiscoveryEncryptionKey())

  const id3 = await IdentityKey.from({ mnemonic: IdentityKey.generateMnemonic() })

  const enc1b = id3.getEncryptionKey(profile1.publicKey)
  const enc2b = id3.getEncryptionKey(profile2.publicKey)

  t.unlike(enc1, enc1b)
  t.unlike(enc2, enc2b)
  t.unlike(id.getProfileDiscoveryEncryptionKey(), id3.getProfileDiscoveryEncryptionKey())
})

test('v0 proof', async function (t) {
  const mnemonic = IdentityKey.generateMnemonic()
  const device = crypto.keyPair()

  const attestedData = b4a.from('attested data')

  const proof = await IdentityKey.bootstrap({ mnemonic }, device.publicKey)

  const decoded = c.decode(ProofEncoding, proof)
  decoded.version = 0

  const encoded = c.encode(ProofEncoding, decoded)

  const auth = IdentityKey.verify(proof, null)

  t.unlike(auth, null)

  t.is(IdentityKey.verify(proof), null)
  t.exception(() => IdentityKey.attestData(attestedData, device, encoded))
  t.exception(() => IdentityKey.attestDevice(device.publicKey, device, encoded))
})
