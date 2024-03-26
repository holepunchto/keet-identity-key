const c = require('compact-encoding')
const b4a = require('b4a')

const KeyChain = require('./lib/keychain')
const { sign, verify, hash } = require('./lib/crypto')

const {
  ProofEncoding,
  AttestedData,
  AttestedDevice,
  ReceiptEncoding
} = require('./lib/encoding')

const VERSION = 0
const KEET_TYPE = 5338

const NS_PROFILE_DISC_ENC = hash(b4a.from('profile discovery'))

module.exports = class IdentityKey {
  constructor (keyChain) {
    this.keyChain = keyChain

    this.identityKeyPair = this.keyChain.get(identityKeyPath(0))
    this.profileDiscoveryKeyPair = this.keyChain.get(discoveryCorePath(0))
  }

  static generateMnemonic () {
    return KeyChain.generateMnemonic()
  }

  static deriveSeed (mnemonic) {
    return KeyChain.deriveSeed(mnemonic)
  }

  get identityPublicKey () {
    return this.identityKeyPair.publicKey
  }

  get profileDiscoveryPublicKey () {
    return this.profileDiscoveryKeyPair.publicKey
  }

  getProfileDiscoveryEncryptionKey () {
    return this.keyChain.getSymmetricKey(encryptionKeyPath(NS_PROFILE_DISC_ENC))
  }

  getEncryptionKey (profileKey) {
    return this.keyChain.getSymmetricKey(encryptionKeyPath(profileKey))
  }

  bootstrap (device) {
    return IdentityKey.bootstrap({ identity: this.identityKeyPair }, device)
  }

  clear () {
    this.keyChain.clear()
    this.identityKeyPair.secretKey.fill(0)
    this.profileDiscoveryKeyPair.secretKey.fill(0)
  }

  static bootstrap ({ identity, seed, mnemonic }, device) {
    if (!identity) {
      const identityPath = identityKeyPath(0) // accountIndex unused for now
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

  static from ({ seed, mnemonic }) {
    const keyChain = KeyChain.from({ seed, mnemonic })

    return new IdentityKey(keyChain)
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

    const receipt = c.encode(ReceiptEncoding, { epoch })

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
    const { epoch } = c.decode(ReceiptEncoding, opts.receipt)
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

function keyPath (accountIndex, index) {
  // https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
  const purpose = 48 // SLIP-48 wallet
  const role = 0 // owner

  return [purpose, KEET_TYPE, role, accountIndex, index]
}

// identityKey -> m/48'/keet'/0'/0'

function identityKeyPath (accountIndex) {
  return keyPath(accountIndex, 0)
}

// identityKey -> m/48'/keet'/0'/1'

function discoveryCorePath (accountIndex) {
  return keyPath(accountIndex, 1)
}

// slip21 derivations
// https://github.com/satoshilabs/slips/blob/master/slip-0021.md

function symmetricPath (...path) {
  const purpose = 'SLIP-0021' // SLIP-21 wallet
  const namespace = 'keet-identity-key' // keet

  return [purpose, namespace, ...path]
}

// encryptionKey  -> m/SLIP-10/keet-identity-key/account/"encryption key"

function encryptionKeyPath (profileKey) {
  return symmetricPath(profileKey.toString('hex'), 'encryption key')
}
