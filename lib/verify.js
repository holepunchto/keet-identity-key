const c = require('compact-encoding')
const b4a = require('b4a')

const { verify: verifySignature, hash } = require('./crypto')

const {
  ProofEncoding,
  AttestedData,
  AttestedDevice,
  ReceiptEncoding
} = require('./encoding')

const PROOF_VERSION = 1

module.exports = verify
module.exports.PROOF_VERSION = PROOF_VERSION

function verify (proof, attestedData, opts = {}) {
  if (b4a.isBuffer(proof)) {
    proof = c.decode(ProofEncoding, proof)
  }

  if (!validateProof(proof, attestedData, opts)) {
    return null
  }

  const { epoch, identity, chain } = proof

  const candidate = getLastKey(chain) || identity

  if (opts.expectedDevice) {
    if (!b4a.equals(candidate, opts.expectedDevice)) return null
  }

  let parent = identity

  // verify chain
  for (let i = 0; i < chain.length; i++) {
    const { publicKey, signature } = chain[i]

    const signable = c.encode(AttestedDevice, {
      epoch,
      identity,
      device: publicKey
    })

    if (!verifySignature(signable, signature, parent)) {
      return null
    }

    parent = publicKey
  }

  if (proof.data) {
    const signable = c.encode(AttestedData, {
      epoch,
      identity,
      data: hash(attestedData)
    })

    if (!verifySignature(signable, proof.data.signature, parent)) {
      return null
    }
  }

  const receipt = c.encode(ReceiptEncoding, { epoch })

  return {
    receipt,
    identityPublicKey: identity,
    devicePublicKey: candidate
  }
}

function validateProof (proof, attestedData, opts = {}) {
  // version 0 is ignored
  if (proof.version === 0) return false

  // validate version
  if (proof.version > PROOF_VERSION) return false

  // verify epoch
  if (opts.receipt) {
    const { epoch } = c.decode(ReceiptEncoding, opts.receipt)
    if (proof.epoch < epoch) return false
  }

  // verify identity
  if (opts.expectedIdentity) {
    if (!b4a.equals(proof.identity, opts.expectedIdentity)) return false
  }

  return validateAttestedData(proof.data, attestedData)
}

function validateAttestedData (data, attestedData) {
  if (!data && attestedData) return false
  return true
}

function getLastKey (chain) {
  if (!chain.length) return null

  const last = chain[chain.length - 1]
  return last.publicKey
}
