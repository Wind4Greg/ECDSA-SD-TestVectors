/* Checking encoding of public keys for ECDSA
   Keys from RFC6979 and draft did:key document
   https://w3c-ccg.github.io/did-method-key/#p-384
*/

import { p256 } from '@noble/curves/p256'
import { p384 } from '@noble/curves/p384'
import { hexToBytes, bytesToHex, concatBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import varint from 'varint'
import { access, writeFile, mkdir } from 'fs/promises'
import { encode, decode } from 'base58-universal'

// Multicodec information from https://github.com/multiformats/multicodec/
/*
name        tag     code    status      description
p256-pub	key	    0x1200	draft	    P-256 public Key (compressed)
p384-pub	key	    0x1201	draft	    P-384 public Key (compressed)
p256-priv key	    0x1306	draft	    P-256 private key
p384-priv key	    0x1307	draft	    P-384 private key
*/

const P256_PUB_PREFIX = 0x1200
const P384_PUB_PREFIX = 0x1201
const P256_PRIV_PREFIX = 0x1306
const P384_PRIV_PREFIX = 0x1307

// Create output directory for the results
const baseDir = './output/KeyCheck/'
const status = await mkdir(baseDir, { recursive: true })

console.log('Multicodec leading bytes in hex for P-256 and P-384 compressed public keys:')
let myBytes = new Uint8Array(varint.encode(P256_PUB_PREFIX))
console.log(`Public P-256 leading bytes: ${bytesToHex(myBytes)}`)
myBytes = new Uint8Array(varint.encode(P384_PUB_PREFIX))
console.log(`Public P-384 leading bytes: ${bytesToHex(myBytes)}\n`)

console.log('Multicodec leading bytes in hex for P-256 and P-384 private keys:')
myBytes = new Uint8Array(varint.encode(P256_PRIV_PREFIX))
console.log(`Private P-256 leading bytes: ${bytesToHex(myBytes)}`)
myBytes = new Uint8Array(varint.encode(P384_PRIV_PREFIX))
console.log(`Private P-384 leading bytes: ${bytesToHex(myBytes)}\n`)

// Example keys from RFC6979

console.log('P256 key example:')
const privateKey = hexToBytes('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721')
const publicKey = p256.getPublicKey(privateKey)
console.log(`P-256 private key length: ${privateKey.length}`)
console.log('P-256 private key hex:')
console.log(bytesToHex(privateKey))
const priv256Prefix = new Uint8Array(varint.encode(P256_PRIV_PREFIX)) // Need to use varint on the multicodecs code
const priv256Encoded = base58btc.encode(concatBytes(priv256Prefix, privateKey))
console.log('Private P-256 encoded multikey:')
console.log(priv256Encoded, '\n') // Should start with z42 characters
console.log(`P-256 Pubic key length ${publicKey.length}`)
console.log('P-256 public key in hex:')
console.log(bytesToHex(publicKey))
const p256Prefix = new Uint8Array(varint.encode(P256_PUB_PREFIX)) // Need to use varint on the multicodecs code
const pub256Encoded = base58btc.encode(concatBytes(p256Prefix, publicKey))
console.log('Public P-256 encoded multikey:')
console.log(pub256Encoded, '\n') // Should start with zDn characters
const p256KeyPair = {
  publicKeyMultibase: pub256Encoded,
  privateKeyMultibase: priv256Encoded
}
await writeFile(baseDir + 'p256KeyPair.json', JSON.stringify(p256KeyPair, null, 2))

// Create another P-256 key pair for proofKey example for ECDSA-SD
const proofPrivateKey = hexToBytes('776448934c81996709671ef7d17ea1c054912f1c702c50d25b14b6c1fad13183')
const proofPublicKey = p256.getPublicKey(proofPrivateKey)
const proofPriv256Encoded = base58btc.encode(concatBytes(priv256Prefix, proofPrivateKey))
const proofPub256Encoded = base58btc.encode(concatBytes(p256Prefix, proofPublicKey))
const sdKeyMaterial = {
  ...p256KeyPair,
  proofPublicKeyMultibase: proofPub256Encoded,
  proofPrivateKeyMultibase: proofPriv256Encoded,
  hmacKeyString: '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
}
await writeFile(baseDir + 'SDKeyMaterial.json', JSON.stringify(sdKeyMaterial, null, 2))

const privateKey384 = hexToBytes('6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5')
const publicKey384 = p384.getPublicKey(privateKey384)
console.log(`P-384 private key length: ${privateKey384.length}`)
console.log(bytesToHex(privateKey384))
const priv384Prefix = new Uint8Array(varint.encode(P384_PRIV_PREFIX)) // Need to use varint on the multicodecs code
const priv384Encoded = base58btc.encode(concatBytes(priv384Prefix, privateKey384))
console.log('Private P-384 encoded multikey:')
console.log(priv384Encoded, '\n') // Should start with z2f characters

console.log(`P-384 Pubic key length ${publicKey384.length}`)
console.log('P-384 public key in hex:')
console.log(bytesToHex(publicKey384))
const p384Prefix = new Uint8Array(varint.encode(P384_PUB_PREFIX)) // Need to use varint on the multicodecs code
const pub384Encoded = base58btc.encode(concatBytes(p384Prefix, publicKey384))
console.log('P-384 encoded multikey:')
console.log(pub384Encoded, '\n') // Should start with z82

const p384KeyPair = {
  publicKeyMultibase: pub384Encoded,
  privateKeyMultibase: priv384Encoded
}
await writeFile(baseDir + 'p384KeyPair.json', JSON.stringify(p384KeyPair, null, 2))

// From example 1 ECDSA-2019 P-384 public key
// "zsJV1eTDACogBS8FMj5vXSa51g1CY1y88DR2DGDwTsMTotTGELVH1XTEsFP8ok9q22ssAaqHN5fMgm1kweTABZZNRSc"
// This does not appear to be a valid P-384 key...
// Try: did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9
const ex384multi = 'z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9'
const ex384bytes = base58btc.decode(ex384multi)
console.log('DID:key example P384 key in hex bytes:')
console.log(bytesToHex(ex384bytes))
console.log(`Length of example P-384 key without prefix: ${ex384bytes.length - 2}`)

//
