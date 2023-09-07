/*
    Walking through the steps for verifying a base SD proof.
*/

import { mkdir, readFile, writeFile } from 'fs/promises'
import { klona } from 'klona'
import {
  createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup, selectJsonLd,
  canonicalize, stripBlankNodePrefixes
} from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { localLoader } from './documentLoader.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import cbor from 'cbor'
import { encode } from 'cborg'
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
and value of mandatoryPointers, key of the string "selective" and value of selectivePointers,
and key of the string "combined" and value of combinedPointers.
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
const mandatoryNonMatch = stuff.groups.mandatory.nonMatching // For reverse engineering
console.log('Mandatory indexes:')
console.log([...mandatoryMatch.keys()])
console.log('Non-Mandatory indexes:')
const nonMandatoryIndexes = [...mandatoryNonMatch.keys()]
console.log(nonMandatoryIndexes) // These were used for individual signatures
// Check baseSignature; Need signData = concatBytes(proofHash, proofPublicKey, mandatoryHash)
// canonize proof configuration and hash it
const proofConfig = klona(proof)
proofConfig['@context'] = document['@context']
delete proofConfig.proofValue // Don't forget to remove this
const proofCanon = await jsonld.canonize(proofConfig)
const proofHash = sha256(proofCanon)
console.log(`proofHash: ${bytesToHex(proofHash)}`)
// TODO: mandatory hash...
