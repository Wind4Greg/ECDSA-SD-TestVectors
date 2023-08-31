/*
    Walking through the steps and generating test vectors for the create a
    **derived** selective disclosure proof using selective disclosure primitive
    functions.

    Reference:

    [Add Derived Proof (ecdsa-sd-2023)](https://w3c.github.io/vc-di-ecdsa/#add-derived-proof-ecdsa-sd-2023)

    Key steps:
    1. [createDisclosureData](https://w3c.github.io/vc-di-ecdsa/#createdisclosuredata)
    2. [serializeDerivedProofValue](https://w3c.github.io/vc-di-ecdsa/#serializederivedproofvalue)
*/

import { mkdir, readFile, writeFile } from 'fs/promises'
import {
  createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup, selectJsonLd,
  canonicalize, stripBlankNodePrefixes
} from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { localLoader } from './documentLoader.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import cbor from 'cbor'
import { encode } from 'cborg'
import { base64url } from 'multiformats/bases/base64'

// Create output directory for the test vectors
const baseDir = './output/ecdsa-sd-2023/'
const status = await mkdir(baseDir, { recursive: true })

// Chosen to be tricky as mandatory has "/boards/0/year" and we are going to
// reveal all about board 0
const selectivePointers = ['/boards/0', '/boards/1']

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read base signed document from a file
const document = JSON.parse(
  await readFile(
    new URL(baseDir + 'addSignedSDBase.json', import.meta.url)
  )
)

const options = { documentLoader: localLoader }

/* Create Disclosure Data
The inputs include a JSON-LD document (document), an ECDSA-SD base proof (proof), an array
of JSON pointers to use to selectively disclose statements (selectivePointers), and any
custom JSON-LD API options, such as a document loader). A single object, disclosure data,
is produced as output, which contains the "baseSignature", "publicKey", "signatures" for
"filteredSignatures", "labelMap", "mandatoryIndexes", and "revealDocument" fields.
*/

/* Initialize baseSignature, publicKey, hmacKey, signatures, and mandatoryPointers to the
values of the associated properties in the object returned when calling the algorithm
parseBaseProofValue, passing the proofValue from proof. */

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

// setup HMAC stuff
const hmac = await createHmac({ key: hmacKey })
const labelMapFactoryFunction = createHmacIdLabelMapFunction({ hmac })

// Combine pointers
const combinedPointers = mandatoryPointers.concat(selectivePointers)
/*
Initialize groupDefinitions to a map with the following entries: key of the string "mandatory"
and value of mandatoryPointers, key of the string "selective" and value of selectivePointers,
and key of the string "combined" and value of combinedPointers.
*/
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
// console.log(stuff);
const combinedMatch = stuff.groups.combined.matching
const mandatoryMatch = stuff.groups.mandatory.matching
const selectiveMatch = stuff.groups.selective.matching
let relativeIndex = 0
const mandatoryIndexes = []
/* For each absoluteIndex in the keys in groups.combined.matching, convert the absolute index
   of any mandatory N-Quad to an index relative to the combined output that is to be revealed:

    If groups.mandatory.matching has absoluteIndex as a key, then append relativeIndex to mandatoryIndexes.
    Increment relativeIndex.
*/
combinedMatch.forEach(function (value, absoluteIndex) {
  if (mandatoryMatch.has(absoluteIndex)) {
    mandatoryIndexes.push(relativeIndex)
  }
  relativeIndex++
})
// console.log(mandatoryIndexes);
/* Determine which signatures match a selectively disclosed statement, which requires incrementing
an index counter while iterating over all signatures, skipping over any indexes that match
the mandatory group.
    Initialize index to 0.
    Initialize filteredSignatures to an empty array.
    For each signature in signatures:
        While index is in groups.mandatory.matching, increment index.
        If index is in groups.selective.matching, add signature to filteredSignatures.
        Increment index.
*/
/* Could not figure out this step from the above description so took the code
from https://github.com/digitalbazaar/ecdsa-sd-2023-cryptosuite/blob/main/lib/disclose.js
and used my variable names. Is this just a set difference in disguise???
*/
let index = 0
const filteredSignatures = signatures.filter(() => {
  while (mandatoryMatch.has(index)) {
    index++
  }
  return selectiveMatch.has(index++)
})
// Initialize revealDocument to the result of the "selectJsonLd" algorithm,
// passing document, and combinedPointers as pointers.
// function selectJsonLd({document, pointers, includeTypes = true} = {})
const revealDocument = selectJsonLd({ document, pointers: combinedPointers })
/*
Run the RDF Dataset Canonicalization Algorithm [RDF-CANON] on the joined combinedGroup.deskolemizedNQuads,
passing any custom options, and get the canonical bnode identifier map, canonicalIdMap. Note: This map
includes the canonical blank node identifiers that a verifier will produce when they canonicalize the
reveal document.
*/
const deskolemizedNQuads = stuff.groups.combined.deskolemizedNQuads
let canonicalIdMap = new Map()
// The goal of the below is to get the canonicalIdMap and not the canonical document
await canonicalize(deskolemizedNQuads.join(''),
  { ...options, inputFormat: 'application/n-quads', canonicalIdMap })
canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap)
/* Initialize verifierLabelMap to an empty map. This map will map the canonical blank node identifiers
 the verifier will produce when they canonicalize the revealed document to the blank node identifiers
  that were originally signed in the base proof. (step 13)
*/
const verifierLabelMap = new Map()
/* For each key (inputLabel) and value (verifierLabel) in `canonicalIdMap:
    Add an entry to verifierLabelMap using verifierLabel as the key and the value associated with inputLabel
    as a key in labelMap as the value.
*/
const labelMap = stuff.labelMap
canonicalIdMap.forEach(function (value, key) {
  verifierLabelMap.set(value, labelMap.get(key))
})

/* Return an object with properties matching baseSignature, publicKey, "signatures" for filteredSignatures,
"verifierLabelMap" for labelMap, mandatoryIndexes, and revealDocument.
  **End** of the *createDisclosureData* function
*/
const disclosureData = {
  baseSignature: bytesToHex(baseSignature),
  publicKey: base58btc.encode(proofPublicKey),
  signatures: filteredSignatures.map(sig => bytesToHex(sig)),
  labelMap: [...verifierLabelMap],
  mandatoryIndexes,
  revealDocument
}
writeFile(baseDir + 'derivedDisclosureData.json', JSON.stringify(disclosureData, null, 2))

// Initialize newProof to a shallow copy of proof.
const newProof = Object.assign({}, proof)
/* 3.4.7 serializeDerivedProofValue
  The following algorithm serializes a derived proof value. The required inputs are a base signature
  (baseSignature), public key (publicKey), an array of signatures (signatures), a label map (labelMap),
  and an array of mandatory indexes (mandatoryIndexes). A single derived proof value, serialized as a byte string,
  is produced as output.
*/
/* Initialize compressedLabelMap to the result of calling the algorithm in Section 3.4.5
  compressLabelMap, passing labelMap as the parameter.
*/
/*  The following algorithm compresses a label map. The required inputs are label map (labelMap).
    The output is a compressed label map.

    Initialize map to an empty map.
    For each entry (k, v) in labelMap:
        Add an entry to map with a key that is a base-10 integer parsed from the characters following
        the "c14n" prefix in k and a value that is a byte array resulting from base64url-no-pad-decoding
        the characters after the "u" prefix in v.
    Return map as compressed label map.
*/
const compressLabelMap = new Map()
verifierLabelMap.forEach(function (v, k) {
  const key = parseInt(k.split('c14n')[1])
  const value = base64url.decode(v)
  compressLabelMap.set(key, value)
})

/*  Initialize a byte array, proofValue, that starts with the ECDSA-SD disclosure proof header
  bytes 0xd9, 0x5d, and 0x01.
  Initialize components to an array with five elements containing the values of: baseSignature,
  publicKey, signatures, compressedLabelMap, and mandatoryIndexes.
  CBOR-encode components and append it to proofValue.
  Return the derived proof as a string with the multibase-base64url-no-pad-encoding of proofValue.
  That is, return a string starting with "u" and ending with the base64url-no-pad-encoded value of proofValue.
*/
let derivedProofValue = new Uint8Array([0xd9, 0x5d, 0x01])
const components = [baseSignature, proofPublicKey, filteredSignatures, compressLabelMap, mandatoryIndexes]
// TODO: resolve CBOR encoding/decoding issue
// let cborThing = await cbor.encodeAsync(components);
const cborThing = await encode(components) // trying cborg library's encode
derivedProofValue = concatBytes(derivedProofValue, cborThing)
const derivedProofValueString = base64url.encode(derivedProofValue)
// console.log(derivedProofValueString)
// console.log(`Length of derivedProofValue is ${derivedProofValueString.length} characters`)
/*  Replace proofValue in newProof with the result of calling the algorithm in Section 3.4.7
  serializeDerivedProofValue, passing baseSignature, publicKey, signatures, labelMap, and mandatoryIndexes.
  Set the value of the "proof" property in revealDocument to newProof.
  Return revealDocument as the selectively revealed document. */
newProof.proofValue = derivedProofValueString
revealDocument.proof = newProof
// console.log(JSON.stringify(revealDocument, null, 2));
writeFile(baseDir + 'derivedRevealDocument.json', JSON.stringify(revealDocument, null, 2))
