/*
    Walking through the steps for verifying a base SD proof.
*/
import { mkdir, readFile } from 'fs/promises'
import { klona } from 'klona'
import {
  createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup
} from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { p256 } from '@noble/curves/p256'
import { localLoader } from './documentLoader.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'

// Create output directory for the test vectors
const baseDir = './output/ecdsa-sd-2023/'
const status = await mkdir(baseDir, { recursive: true })

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read base signed document from a file
const document = JSON.parse(
  await readFile(
    new URL(baseDir + 'addSignedSDBase.json', import.meta.url)
  )
)

const options = { documentLoader: localLoader }

// parseBaseProofValue:
const proof = document.proof
delete document.proof // IMPORTANT: all work uses document without proof
const proofValue = proof.proofValue // base64url encoded
const proofValueBytes = base64url.decode(proofValue)
// console.log(proofValueBytes.length);
// check header bytes are: 0xd9, 0x5d, and 0x00
if (proofValueBytes[0] !== 0xd9 || proofValueBytes[1] !== 0x5d || proofValueBytes[2] !== 0x00) {
  throw new Error('Invalid proofValue header')
}
const decodeThing = cbor.decode(proofValueBytes.slice(3))
if (decodeThing.length !== 5) {
  throw new Error('Bad length of CBOR decoded proofValue data')
}
const [baseSignature, proofPublicKey, hmacKey, signatures, mandatoryPointers] = decodeThing
const baseProofData = { baseSignature: bytesToHex(baseSignature),
  proofPublicKey: base58btc.encode(proofPublicKey),
  hmacKey: bytesToHex(hmacKey),
  signatures: signatures.map(sig => bytesToHex(sig)),
  mandatoryPointers
}
// setup HMAC stuff
const hmac = await createHmac({ key: hmacKey })
const labelMapFactoryFunction = createHmacIdLabelMapFunction({ hmac })

/*
Initialize groupDefinitions to a map with the following entries: key of the string "mandatory"
and value of mandatoryPointers.
*/
const groups = {
  mandatory: mandatoryPointers
}
const stuff = await canonicalizeAndGroup({
  document,
  labelMapFactoryFunction,
  groups,
  options
})
const mandatoryMatch = stuff.groups.mandatory.matching
const mandatoryNonMatch = stuff.groups.mandatory.nonMatching
// Check baseSignature;
// canonize proof configuration and hash it
const proofConfig = klona(proof)
proofConfig['@context'] = document['@context']
delete proofConfig.proofValue // Don't forget to remove this
const proofCanon = await jsonld.canonize(proofConfig)
const proofHash = sha256(proofCanon)
console.log(`proofHash: ${bytesToHex(proofHash)}`)
const mandatoryCanon = [...mandatoryMatch.values()].join('')
const mandatoryHash = sha256(mandatoryCanon)
console.log(`mandatory hash: ${bytesToHex(mandatoryHash)}`)
const signData = concatBytes(proofHash, proofPublicKey, mandatoryHash)
// Get issuer public key
// console.log(proof.verificationMethod.split('did:key:'))
const encodedPbk = proof.verificationMethod.split('did:key:')[1].split('#')[0]
let pbk = base58btc.decode(encodedPbk)
pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`)
let verificationResult = p256.verify(baseSignature, sha256(signData), pbk)
console.log(`baseSignature verified: ${verificationResult}`)
// Check each non-mandatory nquad signature
const nonMandatory = [...mandatoryNonMatch.values()]
let baseVerified = verificationResult
nonMandatory.forEach((value, index) => {
  verificationResult = p256.verify(signatures[index], sha256(value), proofPublicKey.slice(2))
  console.log(`Signature ${index} verified: ${verificationResult}`)
  baseVerified &&= verificationResult
})
console.log(`Base proof verified: ${baseVerified}`)
