const sodium = require('sodium-universal')
const c = require('compact-encoding')
const assert = require('nanoassert')
const b4a = require('b4a')
const { HMAC } = require('@holepunchto/hmac')
const bip39 = require('@holepunchto/bip39')

const { sign } = require('./crypto')

const MASTER_CHAIN_CODE = b4a.from('ed25519 seed')
const MASTER_SYMMETRIC_CODE = b4a.from('Symmetric key seed')

const HARDENED_OFFSET = 0x80000000

class KeyChain {
  constructor (seed) {
    this.seed = seed

    this._buffer = b4a.alloc(64)

    this.chainKey = this._buffer.subarray(0, 32)
    this.chainCode = this._buffer.subarray(32)

    this.publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    this.secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)

    this._initialise()
  }

  static generateMnemonic () {
    return bip39.generateMnemonic()
  }

  static deriveSeed (mnemonic) {
    return bip39.mnemonicToSeed(mnemonic)
  }

  static from ({ mnemonic, seed }, path) {
    assert(mnemonic || seed, 'No mnemonic or seed was passed.')

    if (!seed) seed = KeyChain.deriveSeed(mnemonic)

    const key = new KeyChain(seed)

    if (!path) return key

    return key.get(path)
  }

  getSymmetricKey (path) {
    const buffer = b4a.alloc(64)

    const chainKey = buffer.subarray(0, 32)
    const key = buffer.subarray(32)

    HMAC.sha512(this.seed, MASTER_SYMMETRIC_CODE, buffer)

    for (const step of path) {
      const label = b4a.alloc(step.length + 1)
      b4a.write(label, step, 1, 'utf8')

      HMAC.sha512(label, chainKey, buffer)
    }

    return key
  }

  get isKeychain () {
    return true
  }

  _initialise (seed) {
    HMAC.sha512(this.seed, MASTER_CHAIN_CODE, this._buffer)
    sodium.crypto_sign_seed_keypair(this.publicKey, this.secretKey, this.chainKey)
  }

  clear () {
    this.secretKey.fill(0)
    this.chainKey.fill(0)
    this.chainCode.fill(0)
  }

  get (path) {
    return this.derive(path)
  }

  sign (signable) {
    return sign(signable, this)
  }

  derive (path) {
    const buffer = b4a.from(this._buffer)

    const chainKey = buffer.subarray(0, 32)
    const chainCode = buffer.subarray(32)

    for (const step of path) {
      const index = ensureHardened(step) // hardened indices are >= 2^31
      HMAC.sha512(encodeDerivationData(chainKey, index), chainCode, buffer)
    }

    return createKeyPair(chainKey)
  }
}

module.exports = KeyChain

function createKeyPair (seed) {
  if (!seed) throw new Error('No seed provided')

  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)

  return {
    publicKey,
    secretKey
  }
}

function encodeDerivationData (key, step) {
  const state = { buffer: b4a.alloc(37), start: 0, end: 37 }

  c.uint8.encode(state, 0)
  c.fixed32.encode(state, key)
  state.buffer.writeUInt32BE(step, state.start)

  state.buffer[33] |= 0x80

  return state.buffer
}

function ensureHardened (n) {
  if (n >= HARDENED_OFFSET) return n
  return n + HARDENED_OFFSET
}
