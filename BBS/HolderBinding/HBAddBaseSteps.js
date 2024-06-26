/*
    Walking through my steps and generating test vectors for  creating
    a base BBS proof with the Anonymous Holder Binding feature.
*/

import { mkdir, readFile, writeFile } from 'fs/promises'
import { createHmac, canonicalizeAndGroup } from '@digitalbazaar/di-sd-primitives'
import { createShuffledIdLabelMapFunction } from '../labelMap.js'
import jsonld from 'jsonld'
import { localLoader } from '../../documentLoader.js'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { API_ID_BLIND_BBS_SHA, numberToBytesBE, prepareGenerators } from '../lib/BBS.js'
import { BlindSign, deserialize_and_validate_commit } from '../lib/BlindBBS.js'
import { klona } from 'klona'
import { base58btc } from 'multiformats/bases/base58'
import { encode as encodeCbor } from 'cbor2'
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
const baseDir = '../output/bbs/HolderBinding/'
const inputDir = '../../input/'
await mkdir(baseDir, { recursive: true })

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read input document from a file
const document = JSON.parse(
  await readFile(new URL(inputDir + 'license.json', import.meta.url)))
// Get commitment with proof from a file
const commitInfo = JSON.parse(
  await readFile(new URL(baseDir + 'commitmentInfo.json', import.meta.url)))
const commitmentWithProof = hexToBytes(commitInfo.commitmentWithProof)

// Zeroth step validate the commitment with proof...
const numCommittedMsgs = 1
const gens = await prepareGenerators(numCommittedMsgs + 2, API_ID_BLIND_BBS_SHA)
try {
  await deserialize_and_validate_commit(commitmentWithProof, gens, API_ID_BLIND_BBS_SHA)
} catch (e) {
  console.log(`Commitment with proof not valid: ${e}`)
}

// Obtain key material and process into byte array format
const keyMaterial = JSON.parse(
  await readFile(new URL(inputDir + 'BBSKeyMaterial.json', import.meta.url)))
// HMAC/PRF key material -- Shared between issuer and holder
const hmacKeyString = keyMaterial.hmacKeyString
const hmacKey = hexToBytes(hmacKeyString)
// Sample long term issuer signing key
const privateKey = BigInt('0x' + keyMaterial.privateKeyHex) // hexToBytes(keyMaterial.privateKeyHex)
const publicKey = hexToBytes(keyMaterial.publicKeyHex)
// BLS12-381 G2 public key prefix 0xeb01
const publicKeyMultibase = base58btc.encode(concatBytes(new Uint8Array([0xeb, 0x01]), publicKey))

const options = { documentLoader: localLoader }

// Missing Step: **Proof Configuration Options**
// Set proof options per draft
const proofConfig = {}
proofConfig.type = 'DataIntegrityProof'
proofConfig.cryptosuite = 'bbs-2023'
proofConfig.created = '2023-08-15T23:36:38Z'
proofConfig.verificationMethod = 'did:key:' + publicKeyMultibase + '#' + publicKeyMultibase
proofConfig.proofPurpose = 'assertionMethod'
proofConfig['@context'] = document['@context']
writeFile(baseDir + 'addProofConfig.json', JSON.stringify(proofConfig, null, 2))
const proofCanon = await jsonld.canonize(proofConfig)
writeFile(baseDir + 'addProofConfigCanon.txt', proofCanon)

// **Transformation Step**
const hmacFunc = await createHmac({ key: hmacKey })
const labelMapFactoryFunction = createShuffledIdLabelMapFunction({ hmac: hmacFunc })

const mandatoryPointers = JSON.parse(
  await readFile(
    new URL(inputDir + 'licenseMandatory.json', import.meta.url)
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
await writeFile(baseDir + 'addBaseDocHMACCanon.json', JSON.stringify(stuff.nquads, null, 2))

// **Hashing Step**
const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8

// 3.3.17 hashMandatoryNQuads
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
// const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)
// const gens = await prepareGenerators(bbsMessages.length + 1, API_ID_BBS_SHA)

// Read signer blind info from a file
const signerBlindInfo = JSON.parse(
  await readFile(new URL(inputDir + 'signerBlindHB.json', import.meta.url)))
const signerBlind = BigInt('0x' + signerBlindInfo.signerBlindHex)
const bbsSignature = await BlindSign(privateKey, publicKey, commitmentWithProof,
  bbsHeader, bbsMessages, signerBlind, API_ID_BLIND_BBS_SHA)
console.log(`Blind BBS signature: ${bytesToHex(bbsSignature)}`)
const signerBlindBytes = numberToBytesBE(signerBlind, 32)

const rawBaseSignatureInfo = {
  bbsSignature: bytesToHex(bbsSignature),
  bbsHeader: bytesToHex(bbsHeader),
  publicKey: bytesToHex(publicKey),
  hmacKey: bytesToHex(hmacKey),
  mandatoryPointers,
  signerBlind: bytesToHex(signerBlindBytes),
  featureOption: 'anonymous_holder_binding'
}
// console.log(rawBaseSignatureInfo);
writeFile(baseDir + 'addRawBaseSignatureInfo.json', JSON.stringify(rawBaseSignatureInfo, null, 2))

// CBOR-encode components and append it to proofValue.
// bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers, and signerBlind

let proofValue = new Uint8Array([0xd9, 0x5d, 0x04])
const components = [bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers,
  signerBlindBytes]
const cborThing = encodeCbor(components)
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
