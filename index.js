const c = require('compact-encoding')
const b4a = require('b4a')

const KeyChain = require('./lib/keychain')
const { sign, verify, hash } = require('./lib/crypto')

const {
  ProofEncoding,
  AttestedData,
  AttestedDevice
} = require('./lib/encoding')

const VERSION = 0
const KEET_TYPE = 5338

module.exports = class IdentityKey {
  static generateMnemonic () {
    return KeyChain.generateMnemonic()
  }

  static deriveSeed (mnemonic) {
    return KeyChain.deriveSeed(mnemonic)
  }

  static from ({ seed, mnemonic, accountIndex = 0 }) {
    if (accountIndex !== 0) {
      throw new Error('Account recovery is not supported yet')
    }

    const keyPair = KeyChain.from({ seed, mnemonic })

    if (!seed) seed = keyPair.seed

    const identityKey = keyPair.get(identityKeyPath(accountIndex))
    const discoveryKey = keyPair.getSymmetricKey(discoveryKeyPath(accountIndex))
    const encryptionKey = keyPair.getSymmetricKey(encryptionKeyPath(accountIndex))

    return {
      identityPublicKey: identityKey.publicKey,
      discoveryKey,
      encryptionKey
    }
  }

  static bootstrap ({ identity, seed, mnemonic, accountIndex = 0 }, device) {
    if (accountIndex !== 0) {
      throw new Error('Account recovery is not supported yet')
    }

    if (!identity) {
      const identityPath = identityKeyPath(accountIndex)
      identity = KeyChain.from({ seed, mnemonic }, identityPath)
    }

    const proof = {
      version: VERSION,
      epoch: Date.now(),
      identity: identity.publicKey,
      chain: []
    }

    return IdentityKey.attestDevice(device, identity, proof)
  }

  static attestDevice (publicKey, parent, proof) {
    if (!proof) return IdentityKey.bootstrap({ identity: parent }, publicKey)

    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    const signable = c.encode(AttestedDevice, {
      epoch: proof.epoch,
      identity: proof.identity,
      device: publicKey
    })

    const signature = sign(signable, parent)

    proof.chain.push({ publicKey, signature })

    return c.encode(ProofEncoding, proof)
  }

  static attestData (attestedData, keyPair, proof) {
    if (attestedData === null) throw new Error('Data is not attestable')

    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    if (!proof) {
      proof = {
        version: VERSION,
        epoch: Date.now(),
        identity: keyPair.publicKey,
        chain: []
      }
    }

    const signable = c.encode(AttestedData, {
      epoch: proof.epoch,
      identity: proof.identity,
      data: hash(attestedData)
    })

    const signature = sign(signable, keyPair)

    proof.chain.push({ signature })

    return c.encode(ProofEncoding, proof)
  }

  static verify (proof, attestedData, opts = {}) {
    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    if (!validateProof(proof, attestedData, opts)) return null

    const { epoch, identity, chain } = proof

    const candidate = getLastKey(chain) || identity

    if (opts.expectedDevice) {
      if (!b4a.equals(candidate, opts.expectedDevice)) return null
    }

    const signedData = {
      epoch,
      identity,
      device: null,
      data: attestedData ? hash(attestedData) : null
    }

    let parent = identity

    // verify chain
    for (let i = 0; i < chain.length; i++) {
      const { publicKey, signature } = chain[i]

      signedData.device = publicKey

      const enc = publicKey ? AttestedDevice : AttestedData
      const signable = c.encode(enc, signedData)

      if (!verify(signable, signature, parent)) {
        return null
      }

      parent = publicKey
    }

    const receipt = c.encode(c.uint64, epoch)

    return {
      receipt,
      identityPublicKey: identity,
      devicePublicKey: candidate
    }
  }
}

function validateProof (proof, attestedData, opts = {}) {
  // validate version
  if (proof.version > VERSION) return false

  // verify epoch
  if (opts.receipt) {
    const epoch = c.decode(c.uint64, opts.receipt)
    if (proof.epoch < epoch) return false
  }

  // verify identity
  if (opts.expectedIdentity) {
    if (!b4a.equals(proof.identity, opts.expectedIdentity)) return false
  }

  return validateAttestedData(proof.chain, attestedData)
}

function validateAttestedData (chain, attestedData) {
  const last = chain[chain.length - 1]

  if (!attestedData && attestedData !== null) return false
  if (attestedData === null && last.publicKey === null) return false
  if (attestedData !== null && last.publicKey !== null) return false

  return true
}

function getLastKey (chain) {
  const last = chain[chain.length - 1]

  if (last.publicKey) return last.publicKey
  if (chain.length === 1) return null

  return chain[chain.length - 2].publicKey
}

// slip48 derivations:
// https://github.com/satoshilabs/slips/blob/master/slip-0048.md

// identityKey -> m/48'/keet'/0'/0'

function identityKeyPath (accountIndex) {
  // https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
  const purpose = 48 // SLIP-48 wallet
  const role = 0 // owner

  return [purpose, KEET_TYPE, role, accountIndex, 0]
}

// slip21 derivations
// https://github.com/satoshilabs/slips/blob/master/slip-0021.md

// discoveryKey  -> m/SLIP-10/keet-identity-key/account/"discovery key"
// encryptionKey  -> m/SLIP-10/keet-identity-key/account/"encryption key"

function discoveryKeyPath (accountIndex) {
  const purpose = 'SLIP-0021' // SLIP-21 wallet
  const namespace = 'keet-identity-key' // keet
  const account = accountIndex.toString(10).padStart(4, '0') // owner

  return [purpose, namespace, account, 'discovery key']
}

function encryptionKeyPath (accountIndex) {
  const purpose = 'SLIP-0021' // SLIP-21 wallet
  const namespace = 'keet-identity-key' // keet
  const account = accountIndex.toString(10).padStart(4, '0') // owner

  return [purpose, namespace, account, 'discovery key']
}
