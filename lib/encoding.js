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
    c.uint.preencode(state, a.version)
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

const DataAttestation = {
  preencode (state, proof) {
    c.uint.preencode(state, ATTESTED_DATA)
    c.fixed64.preencode(state, proof.signature)
  },
  encode (state, proof) {
    c.uint.encode(state, ATTESTED_DEVICE)
    c.fixed64.encode(state, proof.signature)
  },
  decode (state) {
    return {
      type: c.uint.decode(state),
      signature: c.fixed64.decode(state)
    }
  }
}

const IntermediateProof = {
  preencode (state, proof) {
    c.uint.preencode(state, ATTESTED_DEVICE)
    c.fixed32.preencode(state, proof.publicKey)
    c.fixed64.preencode(state, proof.signature)
  },
  encode (state, proof) {
    c.uint.encode(state, ATTESTED_DEVICE)
    c.fixed32.encode(state, proof.publicKey)
    c.fixed64.encode(state, proof.signature)
  },
  decode (state) {
    return {
      type: c.uint.decode(state),
      publicKey: c.fixed32.decode(state),
      signature: c.fixed64.decode(state)
    }
  }
}

const IntermediateProofArray = c.array(IntermediateProof)

const ProofEncoding = {
  preencode (state, proof) {
    c.uint.preencode(state, proof.version)
    Epoch.preencode(state, proof.epoch)
    c.fixed32.preencode(state, proof.identity)
    IntermediateProofArray.preencode(state, proof.chain)

    let flags = 0
    if (proof.data) flags |= 1
    c.uint.preencode(state, flags)

    if (proof.data) DataAttestation.preencode(state, proof.data)
  },
  encode (state, proof) {
    c.uint.encode(state, proof.version)
    Epoch.encode(state, proof.epoch)
    c.fixed32.encode(state, proof.identity)
    IntermediateProofArray.encode(state, proof.chain)

    let flags = 0
    if (proof.data) flags |= 1
    c.uint.encode(state, flags)

    if (proof.data) DataAttestation.encode(state, proof.data)
  },
  decode (state) {
    const version = c.uint.decode(state)

    // ignore v0 proofs
    if (version === 0) {
      return {
        version: 0,
        epoch: null,
        identity: null,
        chain: []
      }
    }

    const epoch = Epoch.decode(state)
    const identity = c.fixed32.decode(state)
    const chain = IntermediateProofArray.decode(state)

    const flags = c.uint.decode(state)
    const data = flags & 1 ? DataAttestation.decode(state) : null

    return {
      version,
      epoch,
      identity,
      chain,
      data
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
  ATTESTED_DEVICE,
  ATTESTED_DATA,
  AttestedDevice,
  AttestedData,
  ProofEncoding,
  ReceiptEncoding
}
