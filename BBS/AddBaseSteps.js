/*
    Walking through my steps and generating test vectors for  creating
    a base BBS proof using selective disclosure primitive functions. The higher
    level steps are *transformation*, *hashing*, and *serialization*.
*/

import { mkdir, readFile, writeFile } from 'fs/promises'
import { createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup } from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { localLoader } from '../documentLoader.js'
import { sha256 } from '@noble/hashes/sha256'
import { hmac } from '@noble/hashes/hmac'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { messages_to_scalars, prepareGenerators, publicFromPrivate, sign, verify } from '@grottonetworking/bbs-signatures'
import { klona } from 'klona'
import varint from 'varint'
import { base58btc } from 'multiformats/bases/base58'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'
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
const status = await mkdir(baseDir, { recursive: true })

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read input document from a file
const document = JSON.parse(
  await readFile(new URL('../input/windDoc.json', import.meta.url)))

// Obtain key material and process into byte array format
const keyMaterial = JSON.parse(
  await readFile(new URL('../input/BBSKeyMaterial.json', import.meta.url)))
// HMAC/PRF key material -- Shared between issuer and holder
const hmacKeyString = keyMaterial.hmacKeyString
const hmacKey = hexToBytes(hmacKeyString)
// Sample long term issuer signing key
const privateKey = hexToBytes(keyMaterial.privateKeyHex)
const publicKey = hexToBytes(keyMaterial.publicKeyHex)
// BLS12-381 G2 public key prefix 0xeb01
const publicKeyMultibase = base58btc.encode(concatBytes(new Uint8Array([0xeb, 0x01]), publicKey))

const options = { documentLoader: localLoader }

// Missing Step: **Proof Configuration Options**
// Set proof options per draft
const proofConfig = {}
proofConfig.type = 'DataIntegrityProof'
proofConfig.cryptosuite = 'ecdsa-sd-2023'
proofConfig.created = '2023-08-15T23:36:38Z'
proofConfig.verificationMethod = 'did:key:' + publicKeyMultibase + '#' + publicKeyMultibase
proofConfig.proofPurpose = 'assertionMethod'
proofConfig['@context'] = document['@context']
writeFile(baseDir + 'addProofConfig.json', JSON.stringify(proofConfig, null, 2))
const proofCanon = await jsonld.canonize(proofConfig)
writeFile(baseDir + 'addProofConfigCanon.txt', proofCanon)

// **Transformation Step**

const hmacFunc = await createHmac({ key: hmacKey })
const labelMapFactoryFunction = createHmacIdLabelMapFunction({ hmac: hmacFunc })

/* Initialize groupDefinitions to a map with an entry with a key of the string
   "mandatory" and a value of mandatoryPointers. */
const mandatoryPointers = JSON.parse(
  await readFile(
    new URL('../input/windMandatory.json', import.meta.url)
  )
)
const groups = { mandatory: mandatoryPointers }

const stuff = await canonicalizeAndGroup({ document, labelMapFactoryFunction, groups, options })
// console.log(stuff.groups);
const mandatory = stuff.groups.mandatory.matching
const nonMandatory = stuff.groups.mandatory.nonMatching
// As output the transformation algorithm wants us to return an object with
// "mandatoryPointers" set to mandatoryPointers, "mandatory" set to mandatory,
// "nonMandatory" set to nonMandatory, and "hmacKey" set to hmacKey.
const transformed = { mandatoryPointers, mandatory, nonMandatory, hmacKey }
// Converting maps to arrays of entries for test vector production not required
// for algorithm.
const transformOutput = { mandatoryPointers, mandatory, nonMandatory, hmacKeyString }
await writeFile(baseDir + 'addBaseTransform.json', JSON.stringify(transformOutput, replacerMap, 2))
// For illustration purposes only show the canonicalized document nquads
const documentCanonQuads = await jsonld.canonize(document) // block of text
const documentCanon = documentCanonQuads.split('\n').slice(0, -1).map(q => q + '\n') // array
await writeFile(baseDir + 'addBaseDocCanon.json', JSON.stringify(documentCanon, null, 2))
// HMAC based bnode replacement function
const bnodeIdMap = new Map() // Keeps track of old blank node ids and their replacements
function hmacID (bnode) {
  if (bnodeIdMap.has(bnode)) {
    return bnodeIdMap.get(bnode)
  }
  // console.log(`bnode: ${bnode}`)
  const hmacBytes = hmac(sha256, hmacKey, bnode.split('_:')[1]) // only use the c14nx part
  const newId = '_:' + base64url.encode(hmacBytes)
  bnodeIdMap.set(bnode, newId)
  return newId
}
// Using JavaScripts string replace with global regex and above replacement function
const hmacQuads = documentCanonQuads.replace(/(_:c14n[0-9]+)/g, hmacID)
// console.log(hmacQuads)
// console.log(bnodeIdMap)
const sortedHMACQuads = hmacQuads.split('\n').slice(0, -1).map(q => q + '\n').sort()
await writeFile(baseDir + 'addBaseDocHMACCanon.json', JSON.stringify(sortedHMACQuads, null, 2))

/* **Hashing Step**
   "The required inputs to this algorithm are a transformed data document (transformedDocument)
   and canonical proof configuration (canonicalProofConfig). A hash data value represented as an
   object is produced as output. " */
const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8

// 3.3.17 hashMandatoryNQuads
// Initialize bytes to the UTF-8 representation of the joined mandatory N-Quads.
// Initialize mandatoryHash to the result of using hasher to hash bytes.
// Return mandatoryHash.
const mandatoryHash = sha256([...mandatory.values()].join(''))
// Initialize hashData as a deep copy of transformedDocument and add proofHash as
// "proofHash" and mandatoryHash as "mandatoryHash" to that object.
const hashData = klona(transformed)
hashData.proofHash = proofHash
hashData.mandatoryHash = mandatoryHash
// For test vector purposes convert maps to arrays of pairs and uint8arrays to hex
// and don't rewrite the transformed information.
const hashDataOutput = {}
hashDataOutput.proofHash = bytesToHex(proofHash)
hashDataOutput.mandatoryHash = bytesToHex(mandatoryHash)
writeFile(baseDir + 'addHashData.json', JSON.stringify(hashDataOutput, null, 2))

/* Create BBS signature */
const bbsHeader = concatBytes(proofHash, mandatoryHash)
const te = new TextEncoder()
const bbsMessages = [...nonMandatory.values()].map(txt => te.encode(txt)) // must be byte arrays
const msgScalars = await messages_to_scalars(bbsMessages)
const gens = await prepareGenerators(bbsMessages.length)
const bbsSignature = await sign(privateKey, publicKey, bbsHeader, msgScalars, gens)
console.log(`BBS signature: ${bytesToHex(bbsSignature)}`)

const rawBaseSignatureInfo = {
  bbsSignature: bytesToHex(bbsSignature),
  mandatoryPointers
}
// console.log(rawBaseSignatureInfo);
writeFile(baseDir + 'addRawBaseSignatureInfo.json', JSON.stringify(rawBaseSignatureInfo, null, 2))

// CBOR-encode components and append it to proofValue.

let proofValue = new Uint8Array([0xd9, 0x5d, 0x00]) // TODO: change to something BBS specific
const components = [bbsSignature, hmacKey, mandatoryPointers]
const cborThing = await cbor.encodeAsync(components)
proofValue = concatBytes(proofValue, cborThing)
const baseProof = base64url.encode(proofValue)
console.log(baseProof)
console.log(`Length of baseProof is ${baseProof.length} characters`)

// Construct and Write Signed Document
const signedDocument = klona(document)
delete proofConfig['@context']
signedDocument.proof = proofConfig
signedDocument.proof.proofValue = baseProof
console.log(JSON.stringify(signedDocument, null, 2))
writeFile(baseDir + 'addSignedSDBase.json', JSON.stringify(signedDocument, null, 2))
