const test = require('brittle')
const b4a = require('b4a')
const KeyChain = require('../lib/keychain')

test('slip10 - basic', async function (t) {
  const mnemonic = KeyChain.generateMnemonic()
  const root = await KeyChain.from({ mnemonic })

  t.ok(root.publicKey)
})

// vectors taken from https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// note: the leading 0-bytes in public key vectors are omitted as libsodium public keys are 32 bytes

test('slip10 vector', async t => {
  const vector = [
    '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c',
    '1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187',
    'ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1',
    '8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c',
    '3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a'
  ]

  const seed = b4a.from('000102030405060708090a0b0c0d0e0f', 'hex')
  const root = await KeyChain.from({ seed })

  const chainCode = b4a.from('90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb', 'hex')
  const privateKey = b4a.from('2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7', 'hex')
  const publicKey = b4a.from('a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed', 'hex')

  t.alike(root.chainCode, chainCode)
  t.alike(root.chainKey, privateKey)
  t.alike(root.publicKey, publicKey)

  {
    const path = [0]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[0], 'hex'))
  }

  {
    const path = [0, 1]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[1], 'hex'))
  }

  {
    const path = [0, 1, 2]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[2], 'hex'))
  }

  {
    const path = [0, 1, 2, 2]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[3], 'hex'))
  }

  {
    const path = [0, 1, 2, 2, 1000000000]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[4], 'hex'))
  }
})

test('slip10 vector 2', async t => {
  const vector = [
    '86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037',
    '5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d',
    '2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45',
    'e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b',
    '47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0'
  ]

  const seed = b4a.from('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542', 'hex')

  const root = await KeyChain.from({ seed })

  const chainCode = b4a.from('ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b', 'hex')
  const privateKey = b4a.from('171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012', 'hex')
  const publicKey = b4a.from('8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a', 'hex')

  t.alike(root.chainCode, chainCode)
  t.alike(root.chainKey, privateKey)
  t.alike(root.publicKey, publicKey)

  {
    const path = [0]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[0], 'hex'))
  }

  {
    const path = [0, 2147483647]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[1], 'hex'))
  }

  {
    const path = [0, 2147483647, 1]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[2], 'hex'))
  }

  {
    const path = [0, 2147483647, 1, 2147483646]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[3], 'hex'))
  }

  {
    const path = [0, 2147483647, 1, 2147483646, 2]
    const next = root.get(path)

    t.alike(next.publicKey, b4a.from(vector[4], 'hex'))
  }
})
