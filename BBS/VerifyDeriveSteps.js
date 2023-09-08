/*
    Walking through the steps and generating test vectors for verifying a derived
    BBS selective disclosure proof using selective disclosure primitive functions.
*/

import { mkdir, readFile, writeFile } from 'fs/promises'
import { createLabelMapFunction, labelReplacementCanonicalizeJsonLd } from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { localLoader } from '../documentLoader.js'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { klona } from 'klona'
import { base58btc } from 'multiformats/bases/base58'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'
import {
  messages_to_scalars as msgsToScalars, prepareGenerators, numUndisclosed,
  proofVerify
} from '@grottonetworking/bbs-signatures'

// Create output directory for the results
const baseDir = './output/bbs/'
await mkdir(baseDir, { recursive: true })

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read base signed document from a file 'revealDocument.json', 'DBderivedCredential.json'
const document = JSON.parse(
  await readFile(
    new URL(baseDir + 'derivedRevealDocument.json', import.meta.url)
  )
)

const options = { documentLoader: localLoader }

// *Create Verify Data*

const proof = document.proof
const proofValue = proof.proofValue
const proofConfig = klona(document.proof)
delete proofConfig.proofValue
proofConfig['@context'] = document['@context']
delete document.proof // **IMPORTANT** from now on we work with the document without proof!!!!!!!
const proofCanon = await jsonld.canonize(proofConfig)
const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8

// console.log(`proofHash: ${bytesToHex(proofHash)}`);
// **Parse Derived Proof Value BBS** [bbsProof, compressLabelMap, adjMandatoryIndexes, adjSelectiveIndexes]
if (!proofValue.startsWith('u')) {
  throw new Error('proofValue not a valid multibase-64-url encoding')
}
const decodedProofValue = base64url.decode(proofValue)
// check header bytes are: 0xd9, 0x5d, and 0x01
if (decodedProofValue[0] !== 0xd9 || decodedProofValue[1] !== 0x5d || decodedProofValue[2] !== 0x01) {
  throw new Error('Invalid proofValue header')
}
const decodeThing = cbor.decode(decodedProofValue.slice(3))
if (decodeThing.length !== 4) {
  throw new Error('Bad length of CBOR decoded proofValue data')
}
const [bbsProof, labelMapCompressed, mandatoryIndexes, adjSelectedIndexes] = decodeThing
// console.log(baseSignature, typeof baseSignature);
if (!(labelMapCompressed instanceof Map)) {
  throw new Error('Bad label map in proofValue')
}
labelMapCompressed.forEach(function (value, key) {
  if (!Number.isInteger(key) || value.length !== 32) {
    throw new Error('Bad key or value in compress label map in proofValue')
  }
})
if (!Array.isArray(mandatoryIndexes)) {
  throw new Error('mandatory indexes is not an array in proofValue')
}
mandatoryIndexes.forEach(value => {
  if (!Number.isInteger(value)) {
    throw new Error('Value in mandatory indexes  is not an integer')
  }
})
const labelMap = new Map()
labelMapCompressed.forEach(function (v, k) {
  const key = 'c14n' + k
  const value = base64url.encode(v)
  labelMap.set(key, value)
})
// console.log(labelMap);
// Could use a test vector here
const derivedProofValue = {
  bbsProof: bytesToHex(bbsProof),
  labelMap: [...labelMap],
  mandatoryIndexes
}
// console.log(labelMap);
writeFile(baseDir + 'verifyDerivedProofValue.json', JSON.stringify(derivedProofValue, null, 2))

// Initialize labelMapFactoryFunction to the result of calling the "createLabelMapFunction" algorithm.
const labelMapFactoryFunction = await createLabelMapFunction({ labelMap })
/* Initialize nquads to the result of calling the "labelReplacementCanonicalize" algorithm, passing
  document, labelMapFactoryFunction, and any custom JSON-LD API options. Note: This step transforms
  the document into an array of canonical N-Quads with pseudorandom blank node identifiers based on
  labelMap.
*/
const nquads = await labelReplacementCanonicalizeJsonLd({
  document,
  labelMapFactoryFunction,
  options
})
writeFile(baseDir + 'verifyNQuads.json', JSON.stringify(nquads, null, 2))
const mandatory = []
const nonMandatory = []
nquads.forEach(function (value, index) {
  if (mandatoryIndexes.includes(index)) {
    mandatory.push(value)
  } else {
    nonMandatory.push(value)
  }
})
const mandatoryHash = sha256(mandatory.join(''))

// Get public key
console.log(proof.verificationMethod.split('did:key:'))
//
const encodedPbk = proof.verificationMethod.split('did:key:')[1].split('#')[0]
console.log(encodedPbk)
let pbk = base58btc.decode(encodedPbk)
pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`)

/* Verify BBS Proof */
const bbsHeader = concatBytes(proofHash, mandatoryHash)
const te = new TextEncoder()
const bbsMessages = [...nonMandatory.values()].map(txt => te.encode(txt)) // must be byte arrays
const msgScalars = await msgsToScalars(bbsMessages)
const L = numUndisclosed(bbsProof) + msgScalars.length
const gens = await prepareGenerators(L) // Generate enough for all messages
const ph = new Uint8Array() // Not using presentation header currently
const verified = await proofVerify(pbk, bbsProof, bbsHeader, ph, msgScalars,
  adjSelectedIndexes, gens)
console.log(`Derived proof verified: ${verified}`)
