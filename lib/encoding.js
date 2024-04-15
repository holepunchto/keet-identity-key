const c = require('compact-encoding')

const ATTESTED_DEVICE = 0
const ATTESTED_DATA = 1

const Epoch = {
  preencode (state, e) {
    c.uint64.preencode(state, Math.floor(e / 1000))
  },
  encode (state, e) {
    c.uint64.encode(state, Math.floor(e / 1000))
  },
  decode (state) {
    return c.uint64.decode(state) * 1000
  }
}

const AttestedDevice = {
  preencode (state, a) {
    c.uint.preencode(state, a.version)
    c.uint8.preencode(state, ATTESTED_DEVICE)
    Epoch.preencode(state, a.epoch)
    c.fixed32.preencode(state, a.identity)
    c.fixed32.preencode(state, a.device)
  },
  encode (state, a) {
    c.uint.encode(state, a.version)
    c.uint8.encode(state, ATTESTED_DEVICE)
    Epoch.encode(state, a.epoch)
    c.fixed32.encode(state, a.identity)
    c.fixed32.encode(state, a.device)
  },
  decode (state) {
    throw new Error('Signed data should only be encoded')
  }
}

const AttestedData = {
  preencode (state, a) {
    c.uint.encode(state, a.version)
    c.uint8.preencode(state, ATTESTED_DATA)
    Epoch.preencode(state, a.epoch)
    c.fixed32.preencode(state, a.identity)
    c.fixed32.preencode(state, a.data)
  },
  encode (state, a) {
    c.uint.encode(state, a.version)
    c.uint8.encode(state, ATTESTED_DATA)
    Epoch.encode(state, a.epoch)
    c.fixed32.encode(state, a.identity)
    c.fixed32.encode(state, a.data)
  },
  decode (state) {
    throw new Error('Signed data should only be encoded')
  }
}

const IntermediateProof = {
  preencode (state, proof) {
    c.uint8.preencode(state, ATTESTED_DEVICE)
    if (proof.publicKey) {
      c.fixed32.preencode(state, proof.publicKey)
    }
    c.fixed64.preencode(state, proof.signature)
  },
  encode (state, proof) {
    const type = proof.publicKey ? ATTESTED_DEVICE : ATTESTED_DATA
    c.uint8.encode(state, type)
    if (type === ATTESTED_DEVICE) {
      c.fixed32.encode(state, proof.publicKey)
    }
    c.fixed64.encode(state, proof.signature)
  },
  decode (state) {
    const type = c.uint8.decode(state)
    const publicKey = type === ATTESTED_DEVICE
      ? c.fixed32.decode(state)
      : null

    return {
      publicKey,
      signature: c.fixed64.decode(state)
    }
  }
}

const ProofEncoding = {
  preencode (state, proof) {
    c.uint.preencode(state, proof.version)
    Epoch.preencode(state, proof.epoch)
    c.fixed32.preencode(state, proof.identity)
    c.array(IntermediateProof).preencode(state, proof.chain)
  },
  encode (state, proof) {
    c.uint.encode(state, proof.version)
    Epoch.encode(state, proof.epoch)
    c.fixed32.encode(state, proof.identity)
    c.array(IntermediateProof).encode(state, proof.chain)
  },
  decode (state) {
    const version = c.uint.decode(state)
    const epoch = Epoch.decode(state)
    const identity = c.fixed32.decode(state)
    const chain = c.array(IntermediateProof).decode(state)

    return {
      version,
      epoch,
      identity,
      chain
    }
  }
}

const ReceiptEncoding = {
  preencode (state, receipt) {
    Epoch.preencode(state, receipt.epoch)
  },
  encode (state, receipt) {
    Epoch.encode(state, receipt.epoch)
  },
  decode (state) {
    return {
      epoch: Epoch.decode(state)
    }
  }
}

module.exports = {
  AttestedDevice,
  AttestedData,
  ProofEncoding,
  ReceiptEncoding
}
