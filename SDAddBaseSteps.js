/*
    Walking through the steps to  create ("Add") a based SD proof using Digital
    Bazaar functions. The higher level steps are *transformation*, *hashing*, and
    *serialization*.

    For *transformation* `async function canonicalizeAndGroup({document,
      labelMapFactoryFunction, groups, options})` is used.
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import { createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup } from '@digitalbazaar/di-sd-primitives';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import { p256 } from '@noble/curves/p256';
import {klona} from 'klona';
import varint from 'varint';
import { base58btc } from "multiformats/bases/base58";
import cbor from "cbor";
import { base64url} from "multiformats/bases/base64";

// Create output directory for the results
const baseDir = "./output/ecdsa-sd-2023/";
let status = await mkdir(baseDir, {recursive: true});

// Sample keys
const keyPair = {
  publicKeyMultibase: "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
};
let privateKey = hexToBytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL('./input/windDoc.json', import.meta.url)
    )
  );

const options = {documentLoader: localLoader};

// **Transformation Step**
// Need an HMAC string
let hmacKeyString = '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF';
let hmacKey = hexToBytes(hmacKeyString);
const hmac = await createHmac({key: hmacKey});
const labelMapFactoryFunction = createHmacIdLabelMapFunction({hmac});

// Initialize groupDefinitions to a map with an entry with a key of the string
// "mandatory" and a value of mandatoryPointers.
const mandatoryPointers = JSON.parse(
  await readFile(
    new URL('./input/windMandatory.json', import.meta.url)
  )
);
const groups = {"mandatory": mandatoryPointers };

let stuff = await canonicalizeAndGroup({document, labelMapFactoryFunction, groups, options});
// console.log(stuff.groups);
const mandatory = stuff.groups.mandatory.matching;
const nonMandatory = stuff.groups.mandatory.nonMatching;
// As output the transformation algorithm wants us to return an object with
// "mandatoryPointers" set to mandatoryPointers, "mandatory" set to mandatory,
// "nonMandatory" set to nonMandatory, and "hmacKey" set to hmacKey.
const transformed = {mandatoryPointers, mandatory, nonMandatory, hmacKey};
// Converting maps to arrays of entries for test vector production not required
// for algorithm.
const transformOutput = {mandatoryPointers, mandatory: [...mandatory],
  nonMandatory: [...nonMandatory], hmacKeyString};
// console.log(transformOutput);
await writeFile(baseDir + 'addBaseTransform.json', JSON.stringify(transformOutput, null, 2));

// Missing Step: **Configuration Options**
// Set proof options per draft
let proofConfig = {};
proofConfig.type = "DataIntegrityProof";
proofConfig.cryptosuite = "ecdsa-rdfc-2019";
proofConfig.created = "2023-08-15T23:36:38Z";
proofConfig.verificationMethod = "did:key:" + keyPair.publicKeyMultibase;
proofConfig.proofPurpose = "assertionMethod";
proofConfig["@context"] = document["@context"];
const proofCanon = await jsonld.canonize(proofConfig);
writeFile(baseDir + 'proofConfigCanonECDSA_SD.txt', proofCanon);

/* **Hashing Step**
   "The required inputs to this algorithm are a transformed data document (transformedDocument)
   and canonical proof configuration (canonicalProofConfig). A hash data value represented as an
   object is produced as output. " */
let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
let hashTestVector = {proofHash: bytesToHex(proofHash)};
// 3.3.17 hashMandatoryNQuads
// Initialize bytes to the UTF-8 representation of the joined mandatory N-Quads.
// Initialize mandatoryHash to the result of using hasher to hash bytes.
// Return mandatoryHash.

let mandatoryHash = sha256([...mandatory.values()].join(''));
// Initialize hashData as a deep copy of transformedDocument and add proofHash as
// "proofHash" and mandatoryHash as "mandatoryHash" to that object.
const hashData = klona(transformed);
hashData.proofHash = proofHash;
hashData.mandatoryHash = mandatoryHash;
// For test vector purposes convert maps to arrays of pairs and uint8arrays to hex
const hashDataOutput = klona(transformOutput);
hashDataOutput.proofHash = bytesToHex(proofHash);
hashDataOutput.mandatoryHash = bytesToHex(mandatoryHash);
// console.log(hashDataOutput);
writeFile(baseDir + 'hashData.json', JSON.stringify(hashDataOutput, null, 2));

/* 3.5.5 Base Proof Serialization (ecdsa-sd-2023)
  Initialize proofHash, mandatoryPointers, mandatoryHash, nonMandatory, and hmacKey
  to the values associated with their property names hashData.
*/

// Initialize proofScopedKeyPair to a locally generated P-256 ECDSA key pair.
// Note: This key pair is scoped to the specific proof;
let proofPrivateKey = hexToBytes('776448934c81996709671ef7d17ea1c054912f1c702c50d25b14b6c1fad13183');
let proofPublicKey = p256.getPublicKey(proofPrivateKey);

// Initialize signatures to an array where each element holds the result of digitally signing
// the UTF-8 representation of each N-Quad string in nonMandatory, in order.
let signatures = [];
nonMandatory.forEach(function(value, key){
  let msgHash = sha256(value); // Hash is done outside of the algorithm in noble/curve case.
  let signature = p256.sign(msgHash, proofPrivateKey);
  signatures.push(signature.toCompactRawBytes());
  // console.log(`value: ${value}, sig: ${signature.toCompactHex()}`);
});
// Initialize publicKey to the multikey expression of the public key exported from proofScopedKeyPair.
const P256_PUB_PREFIX = 0x1200;
let p256Prefix = new Uint8Array(varint.encode(P256_PUB_PREFIX)); // Need to use varint on the multicodecs code
let pub256Encoded = base58btc.encode(concatBytes(p256Prefix, proofPublicKey));
console.log(`proofPublicKey multikey: ${pub256Encoded}`);
// 3.4.1 serializeSignData
//The following algorithm serializes the data that is to be signed by the private key associated
// with the base proof verification method. The required inputs are the proof options hash (proofHash),
// the proof-scoped multikey-encoded public key (publicKey), and the mandatory hash (mandatoryHash).
// A single sign data value, represented as series of bytes, is produced as output.
// Return the concatenation of proofHash, publicKey, and mandatoryHash, in that order, as sign data.
let signData = concatBytes(proofHash,base58btc.decode(pub256Encoded), mandatoryHash);
console.log("mandatory hash:");
console.log(mandatoryHash);
console.log(`signData length: ${signData.length}`);
let baseSignature = p256.sign(sha256(signData), privateKey).toCompactRawBytes();
// baseSignature, publicKey, hmacKey, signatures, and mandatoryPointers are inputs to
// 3.4.2 serializeBaseProofValue. This seems like a good test vector
let rawBaseSignatureInfo = { baseSignature: bytesToHex(baseSignature), publicKey: pub256Encoded,
  signatures: signatures.map(sig => bytesToHex(sig)), mandatoryPointers};
// console.log(rawBaseSignatureInfo);
writeFile(baseDir + 'rawBaseSignatureInfo.json', JSON.stringify(rawBaseSignatureInfo, null, 2));

/* 3.4.2 serializeBaseProofValue
The following algorithm serializes the base proof value, including the base signature, public key,
HMAC key, signatures, and mandatory pointers. The required inputs are a base signature baseSignature,
a public key publicKey, an HMAC key hmacKey, an array of signatures, and an array of mandatoryPointers.
A single base proof string value is produced as output.

Initialize a byte array, proofValue, that starts with the ECDSA-SD base proof header bytes 0xd9, 0x5d, and 0x00.

Initialize components to an array with five elements containing the values of: baseSignature, publicKey, hmacKey,
 signatures, and mandatoryPointers.

CBOR-encode components and append it to proofValue.

Initialize baseProof to a string with the multibase-base64url-no-pad-encoding of proofValue. That is, return a
 string starting with "u" and ending with the base64url-no-pad-encoded value of proofValue.
Return baseProof as base proof.

*/

let proofValue = new Uint8Array([0xd9, 0x5d, 0x00]);
let components = [baseSignature, base58btc.decode(pub256Encoded), hmacKey, signatures, mandatoryPointers];
let cborThing = await cbor.encodeAsync(components);
proofValue = concatBytes(proofValue, cborThing);
let baseProof = base64url.encode(proofValue);
console.log(baseProof);
console.log(`Length of baseProof is ${baseProof.length} characters`);

// Construct Signed Document
let signedDocument = klona(document);
delete proofConfig['@context'];
signedDocument.proof = proofConfig;
signedDocument.proof.proofValue = baseProof;

console.log(JSON.stringify(signedDocument, null, 2));
writeFile(baseDir + 'signedSDBase.json', JSON.stringify(signedDocument, null, 2));


