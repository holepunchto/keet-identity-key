# keet-identity-key

Hierarchical keychains that derives deterministic Ed25519 keypairs

```
npm install @holepunchto/keet-identity-key
```

## Usage

``` js
const IdentityKey = require('@holepunchto/keet-hd-key')

const mnemonic = IdentityKey.generateMnemonic()
const id = await IdentityKey.from({ mnemonic })

const proof0 = id.bootstrap(mainDevice.publicKey)
const proof = IdentityKey.attest(auxillaryDevice.publicKey, mainDevice, proof0)

const info = IdentityKey.verify(proof)

if (info === null) {
  // verification failed
} else {
  console.log(b4a.equals(info.identityPublicKey, id.identityPublicKey)) // true
  console.log(b4a.equals(info.publicKey, auxillaryDevice.publicKey)) // true
}
```

## API

#### `mnemonic = IdentityKey.generateMnemonic()`

Generate a new `mnemonic`

#### `seed = IdentityKey.generateSeed(mnemonic)`

Returns a 32-byte buffer with entropy derived from `mnemonic`

#### `const identity = new IdentityKeyPair(keyChain)`

Instantiate a new `IdentityKey`

#### `identity.identityPublicKey`

32-byte public key for the root identity

#### `identity.profileDiscoveryKeyPair`

Key pair to be used for the profile discovery core

#### `identity.profileDiscoveryPublicKey`

32-byte public key for the profile discovery core

#### `identity.profileDiscoveryKeyPair`

Key pair to be used for the profile discovery core

#### `const encryptionKey = identity.getProfileDiscoveryEncryptionKey()`

Encryption key to be used for the profile discovery core

#### `const encryptionKey = identity.getEncryptionKey(profileKey)`

Derive an encrypton key for a given profile

#### `identity.clear()`

Clear all private data from the key

#### `identity = IdentityKey.from({ mnemonic, seed })`

Convenience method for deriving an `IdentityKey` from a mnemonic or seed

#### `proof = identity.bootstrap(deviceKey)`

Bootstrap an intitial `deviceKey`

#### `proof = IdentityKey.bootstrap({ seed, mnemonic }, deviceKey)`

Bootstrap an intitial `deviceKey` using a mnemonic

#### `proof = IdentityKey.attestDevice(device, parent, [proof])`

Use an existing `parent` key pair to attest to another `device` key.

If provided with a `proof` linking `parent` to a given root key, then the returned proof will link `key` back to the same root key.

#### `proof = IdentityKey.attestData(data, keyPair, [proof])`

Create an attestation of arbitrary `data` using `keyPair`.

If a `proof` is provided, the attestation will be appended to the proof and verified as part of it.

`keyPair` should correspond to the last public key in the proof's chain.

#### `info = IdentityKey.verify(proof, attestedData, opts ={ receipt, expectedIndentity, expectedDevice })`

Verify a proof.

Returns `null` if verification fails, otherwise an object with:
- `receipt`: an opaque object that future proofs may be verified against
- `identityPublicKey`: the root public key the proof links to
- `devicePublicKey`: the public key the proof attests to

If no data is attested to, ie. we are just verifying a device key, then `attestedData` should be passed as `null`.

Optionally pass any of `receipt`, `expectedIndentity` or `expectedDevice`. Verification will fail if:

- proof is not valid given against a previous `receipt`
- proof links back to any key other than `expectedIndentity` provided
- proof attests to any key other than `expectedDevice` provided

## License

Apache-2.0
