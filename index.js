const c = require('compact-encoding')
const b4a = require('b4a')

const KeyChain = require('./lib/keychain')
const ProofEncoding = require('./lib/encoding')

// see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
const KEET_TYPE = 0x03ce

// derivation paths
const KEET_ROOT_PATH = [KEET_TYPE, 0, 0] // m/keet'/0'/1'
const KEET_DISCOVERY_PATH = [KEET_TYPE, 1, 0] // m/keet'/1'/0'
const KEET_ENCRYPTION_PATH = [KEET_TYPE, 1, 1] // m/keet'/1'/1'

module.exports = class IdentityKey {
  static generateMnemonic () {
    return KeyChain.generateMnemonic()
  }

  static generateSeed (mnemonic) {
    return KeyChain.generateSeed(mnemonic)
  }

  static from ({ seed, mnemonic }) {
    const keyPair = KeyChain.from({ seed, mnemonic })

    const root = keyPair.get(KEET_ROOT_PATH)

    const discoveryKey = keyPair.get(KEET_DISCOVERY_PATH).secretKey
    const encryptionKey = keyPair.get(KEET_ENCRYPTION_PATH).secretKey

    return {
      root: root.publicKey,
      discoveryKey,
      encryptionKey
    }
  }

  static generate ({ root, seed, mnemonic }, device) {
    if (!root) root = KeyChain.from({ seed, mnemonic }, KEET_ROOT_PATH)

    const proof = {
      timestamp: Date.now(),
      root: root.publicKey,
      chain: []
    }

    return IdentityKey.attest(device, root, proof)
  }

  static attest (key, parent, proof) {
    if (!proof) return IdentityKey.generate({ root: parent }, key)

    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    const signature = KeyChain.sign(key, parent)

    proof.chain.push({ key, signature })

    return c.encode(ProofEncoding, proof)
  }

  static verify (proof, { timestamp = 0, root, publicKey } = {}) {
    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    if (proof.timestamp < timestamp) return null
    if (root && !b4a.equals(proof.root, root)) return null

    const last = proof.chain[proof.chain.length - 1]
    if (publicKey && !b4a.equals(last.key, publicKey)) return null

    for (let i = proof.chain.length - 1; i >= 0; i--) {
      const { key, signature } = proof.chain[i]
      const parent = i === 0 ? proof.root : proof.chain[i - 1].key

      if (!KeyChain.verify(key, signature, parent)) {
        return null
      }
    }

    return {
      timestamp: proof.timestamp,
      root: proof.root,
      publicKey: last.key
    }
  }
}
