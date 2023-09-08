/*
To come up with Derived Proof for BBS we need:

1. BBSSignature (BBS proof input)
2. HMAC key
3. List of non-mandatory messages (BBS proof input)
4. Indexes of selective messages to be revealed (BBS proof input)
5. Need to recreate the header via proofConfig and mandatory disclosure stuff
6. Generate the BBSProofValue (output of BBS proof procedure)
7. serialize via CBOR: BBSProofValue, compressedLabelMap, mandatoryIndexes

*/

import { mkdir, readFile, writeFile } from 'fs/promises'
import {
  createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup, selectJsonLd,
  canonicalize, stripBlankNodePrefixes
} from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { klona } from 'klona'
import { localLoader } from '../documentLoader.js'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import cbor from 'cbor'
import { encode } from 'cborg'
import { sha256 } from '@noble/hashes/sha256'
import { base64url } from 'multiformats/bases/base64'
import { messages_to_scalars as msgsToScalars, prepareGenerators, proofGen } from '@grottonetworking/bbs-signatures'
// For serialization of JavaScript Map via JSON
function replacerMap (key, value) { // See https://stackoverflow.com/questions/29085197/how-do-you-json-stringify-an-es6-map
  if (value instanceof Map) {
    return {
      dataType: 'Map',
      value: Array.from(value.entries()) // or with spread: value: [...value]
    }
  } else {
    return value
  }
}

// Create output directory for the test vectors
const baseDir = './output/bbs/'
await mkdir(baseDir, { recursive: true })

// Get the selective disclosure pointers
const selectivePointers = JSON.parse(
  await readFile(
    new URL('../input/' + 'windSelective.json', import.meta.url)
  )
)
jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read base signed document from a file
const document = JSON.parse(
  await readFile(
    new URL(baseDir + 'addSignedSDBase.json', import.meta.url)
  )
)

const options = { documentLoader: localLoader }

// **Create Disclosure Data**

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

if (decodeThing.length !== 3) {
  throw new Error('Bad length of CBOR decoded proofValue data')
}
const [bbsSignature, hmacKey, mandatoryPointers] = decodeThing
const baseProofData = {
  bbsSignature: bytesToHex(bbsSignature),
  hmacKey: bytesToHex(hmacKey),
  mandatoryPointers
}
await writeFile(baseDir + 'derivedRecoveredBaseData.json', JSON.stringify(baseProofData, replacerMap, 2))
// Combine pointers
const combinedPointers = mandatoryPointers.concat(selectivePointers)
// Creating reveal document from combined pointers
const revealDocument = selectJsonLd({ document, pointers: combinedPointers })
await writeFile(baseDir + 'derivedUnsignedReveal.json', JSON.stringify(revealDocument, replacerMap, 2))
// setup HMAC stuff
const hmac = await createHmac({ key: hmacKey })
const labelMapFactoryFunction = createHmacIdLabelMapFunction({ hmac })

// Initialize group definition so we can figure out BBS messages and indexes
const groups = {
  mandatory: mandatoryPointers,
  selective: selectivePointers,
  combined: combinedPointers
}
const stuff = await canonicalizeAndGroup({
  document,
  labelMapFactoryFunction,
  groups,
  options
})
// console.log(JSON.stringify(stuff, replacerMap, 2))
await writeFile(baseDir + 'derivedAllGroupData.json', JSON.stringify(stuff, replacerMap, 2))
const combinedMatch = stuff.groups.combined.matching
const mandatoryMatch = stuff.groups.mandatory.matching
const mandatoryNonMatch = stuff.groups.mandatory.nonMatching // For reverse engineering
const selectiveMatch = stuff.groups.selective.matching
const combinedIndexes = [...combinedMatch.keys()]
const nonMandatoryIndexes = [...mandatoryNonMatch.keys()]
const selectiveIndexes = [...selectiveMatch.keys()]
const groupIndexes = {
  combinedIndexes,
  mandatoryIndexes: [...mandatoryMatch.keys()],
  nonMandatoryIndexes,
  selectiveIndexes
}
await writeFile(baseDir + 'derivedGroupIndexes.json', JSON.stringify(groupIndexes, replacerMap, 2))
/*
  Compute the "adjusted mandatory indexes" relative to their
  positions in the combined statement list, i.e., find at what position a mandatory
  statement occurs in the list of combined statements.
*/
const adjMandatoryIndexes = []
mandatoryMatch.forEach((value, index) => {
  adjMandatoryIndexes.push(combinedIndexes.indexOf(index))
})
await writeFile(baseDir + 'derivedAdjMandatoryIndexes.json', JSON.stringify({ adjMandatoryIndexes }))
/* Determine which non-mandatory nquad match a selectively disclosed nquad and
  get its index relative to place in the non-mandatory list.
  The non-mandatory nquads are the BBS messages and we need the selective indexes
  relative to this list.
*/
const adjSelectiveIndexes = []
selectiveMatch.forEach((value, index) => {
  const adjIndex = nonMandatoryIndexes.indexOf(index)
  if (adjIndex !== -1) {
    adjSelectiveIndexes.push(adjIndex)
  }
})
// console.log('adjust Signature Indexes:')
// console.log(adjSignatureIndexes)
await writeFile(baseDir + 'derivedAdjSelectiveIndexes.json',
  JSON.stringify({ adjSignatureIndexes: adjSelectiveIndexes }))

// **Create Verifier Label Map**
const deskolemizedNQuads = stuff.groups.combined.deskolemizedNQuads
let canonicalIdMap = new Map()
// The goal of the below is to get the canonicalIdMap and not the canonical document
await canonicalize(deskolemizedNQuads.join(''),
  { ...options, inputFormat: 'application/n-quads', canonicalIdMap })
// console.log(JSON.stringify(canonicalIdMap, replacerMap, 2))
canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap)
// console.log(JSON.stringify(canonicalIdMap, replacerMap, 2))
const verifierLabelMap = new Map()
const labelMap = stuff.labelMap
canonicalIdMap.forEach(function (value, key) {
  verifierLabelMap.set(value, labelMap.get(key))
})

// 6. Generate the BBSProofValue (output of BBS proof procedure)
// Recreate BBS header
const proofConfig = klona(proof)
proofConfig['@context'] = document['@context']
delete proofConfig.proofValue // Don't forget to remove this
const proofCanon = await jsonld.canonize(proofConfig)
const proofHash = sha256(proofCanon)
const mandatoryCanon = [...mandatoryMatch.values()].join('')
const mandatoryHash = sha256(mandatoryCanon)
const bbsHeader = concatBytes(proofHash, mandatoryHash)
// Recreate BBS messages
const te = new TextEncoder()
const bbsMessages = [...mandatoryNonMatch.values()].map(txt => te.encode(txt)) // must be byte arrays
const msgScalars = await msgsToScalars(bbsMessages)
// calc generators -- note in production these values would be cached since they are reusable
const gens = await prepareGenerators(bbsMessages.length)
// Get issuer public key
const encodedPbk = proof.verificationMethod.split('did:key:')[1].split('#')[0]
let pbk = base58btc.decode(encodedPbk)
pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
// console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`)
const ph = new Uint8Array() // Not using presentation header currently
const bbsProof = await proofGen(pbk, bbsSignature, bbsHeader, ph, msgScalars,
  adjSelectiveIndexes, gens)

// 7. serialize via CBOR: BBSProofValue, compressedLabelMap, mandatoryIndexes

const disclosureData = {
  bbsProof: bytesToHex(bbsProof),
  labelMap: verifierLabelMap,
  mandatoryIndexes: adjMandatoryIndexes
}
await writeFile(baseDir + 'derivedDisclosureData.json', JSON.stringify(disclosureData, replacerMap, 2))

// Initialize newProof to a shallow copy of proof.
const newProof = Object.assign({}, proof)
const compressLabelMap = new Map()
verifierLabelMap.forEach(function (v, k) {
  const key = parseInt(k.split('c14n')[1])
  const value = base64url.decode(v)
  compressLabelMap.set(key, value)
})

let derivedProofValue = new Uint8Array([0xd9, 0x5d, 0x01])
const components = [bbsProof, compressLabelMap, adjMandatoryIndexes]
// TODO: resolve CBOR encoding/decoding issue
// let cborThing = await cbor.encodeAsync(components);
const cborThing = await encode(components) // trying cborg library's encode
derivedProofValue = concatBytes(derivedProofValue, cborThing)
const derivedProofValueString = base64url.encode(derivedProofValue)
console.log(derivedProofValueString)
console.log(`Length of derivedProofValue is ${derivedProofValueString.length} characters`)
newProof.proofValue = derivedProofValueString
revealDocument.proof = newProof
// console.log(JSON.stringify(revealDocument, null, 2));
writeFile(baseDir + 'derivedRevealDocument.json', JSON.stringify(revealDocument, null, 2))
