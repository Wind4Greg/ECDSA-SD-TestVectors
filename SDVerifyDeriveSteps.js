/*
    Walking through the steps to verify a derived SD proof using Digital
    Bazaar SD-primitive functions.

    Reference:

    [3.5.7 Verify Derived Proof (ecdsa-sd-2023)](https://w3c.github.io/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023)

    Key initialization step: [3.4.9 createVerifyData](https://w3c.github.io/vc-di-ecdsa/#createverifydata)
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import {createLabelMapFunction, labelReplacementCanonicalizeJsonLd} from '@digitalbazaar/di-sd-primitives';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import { p256 } from '@noble/curves/p256';
import { klona } from 'klona';
import { base58btc } from "multiformats/bases/base58";
import cbor from "cbor";
import { base64url } from "multiformats/bases/base64";

// Create output directory for the results
const baseDir = "./output/ecdsa-sd-2023/";
let status = await mkdir(baseDir, { recursive: true });

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

// Read base signed document from a file 'revealDocument.json', 'DBderivedCredential.json'
let document = JSON.parse(
  await readFile(
    new URL(baseDir + 'revealDocument.json', import.meta.url)
  )
);

const options = { documentLoader: localLoader };

/* Create Verify Data
The following algorithm creates the data needed to perform verification of an ECDSA-SD-protected
verifiable credential. The inputs include a JSON-LD document (document), an ECDSA-SD disclosure proof
(proof), and any custom JSON-LD API options, such as a document loader. A single verify data object
value is produced as output containing the following fields: "baseSignature", "proofHash",
"publicKey", "signatures", "nonMandatory", and "mandatoryHash".
*/
/* Initialize proofHash to the result of perform RDF Dataset Canonicalization [RDF-CANON] on the proof
  options. The hash used is the same as the one used in the signature algorithm, i.e., SHA-256 for a
  P-256 curve. Note: This step can be performed in parallel; it only needs to be completed before
  this algorithm needs to use the proofHash value.
*/
const proof = document.proof;
const proofValue = proof.proofValue;
let proofConfig = klona(document.proof);
delete proofConfig.proofValue;
proofConfig["@context"] = document["@context"];
delete document.proof; // **IMPORTANT** from now on we work with the document without proof!!!!!!!
const proofCanon = await jsonld.canonize(proofConfig);
let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
// console.log(`proofHash: ${bytesToHex(proofHash)}`);
/* 3.4.8 parseDerivedProofValue

The following algorithm parses the components of the derived proof value. The required inputs
are a derived proof value (proofValue). A A single derived proof value value object is produced
as output, which contains a set to five elements, using the names "baseSignature", "publicKey",
"signatures", "labelMap", and "mandatoryIndexes".

    Ensure the proofValue string starts with u, indicating that it is a multibase-base64url-no-pad-encoded
      value, throwing an error if it does not.
    Initialize decodedProofValue to the result of base64url-no-pad-decoding the substring after the
      leading u in proofValue.
    Ensure that the decodedProofValue starts with the ECDSA-SD disclosure proof header bytes 0xd9,
      0x5d, and 0x01, throwing an error if it does not.
    Initialize components to an array that is the result of CBOR-decoding the bytes that follow the
      three-byte ECDSA-SD disclosure proof header. Ensure the result is an array of five elements.
      Ensure the result is an array of five elements: a byte array of length 64, a byte array of
      length 36, an array of byte arrays, each of length 64, a map of integers to byte arrays of
      length 32, and an array of integers, throwing an error if not.
    Replace the fourth element in components using the result of calling the algorithm in Section 3.4.6
      decompressLabelMap, passing the existing fourth element of components as compressedLabelMap.
    Return derived proof value as an object with properties set to the five elements, using the
      names "baseSignature", "publicKey", "signatures", "labelMap", and "mandatoryIndexes", respectively.
*/

if (!proofValue.startsWith('u')) {
  throw new Error('proofValue not a valid multibase-64-url encoding');
}
let decodedProofValue = base64url.decode(proofValue);
// check header bytes are: 0xd9, 0x5d, and 0x01
if (decodedProofValue[0] != 0xd9 || decodedProofValue[1] != 0x5d || decodedProofValue[2] != 0x01) {
  throw new Error("Invalid proofValue header");
}
let decodeThing = cbor.decode(decodedProofValue.slice(3));
/* Ensure the result is an array of five elements.
      Ensure the result is an array of five elements: a byte array of length 64, a byte array of
      length 36, an array of byte arrays, each of length 64, a map of integers to byte arrays of
      length 32, and an array of integers, throwing an error if not.
*/
/* **CAUTION** publicKey is currently encoded in raw bytes with multi-key byte
    header. For a total length of 35 bytes.
*/
if (decodeThing.length != 5) {
  throw new Error("Bad length of CBOR decoded proofValue data");
}
let [baseSignature, publicKey, signatures, labelMapCompressed, mandatoryIndexes] = decodeThing;
// console.log(baseSignature, typeof baseSignature);
if (!baseSignature.BYTES_PER_ELEMENT === 1 && baseSignature.length === 64) {
  throw new Error("Bad baseSignature in proofValue");
}
publicKey = new Uint8Array(publicKey); // Just to make sure convert into byte array
// console.log(`publicKey: ${bytesToHex(publicKey)}`);
// console.log(`publicKey length: ${publicKey.length}`);
// let publicKeyBytes = base58btc.decode(publicKey);
// publicKeyBytes = publicKeyBytes.slice(2, publicKeyBytes.length); // First two bytes are multi-format indicator
// console.log(`Public Key hex: ${bytesToHex(publicKeyBytes)}, Length: ${publicKeyBytes.length}`);
if (!Array.isArray(signatures)) {
  throw new Error("signatures in proof value is not an array");
}
signatures.forEach(function (value) {
  if (!value.BYTES_PER_ELEMENT === 1 && value.length === 64) {
    throw new Error("Bad signature in signatures array in proofValue");
  }
})
if (!labelMapCompressed instanceof Map) {
  throw new Error("Bad label map in proofValue");
}
labelMapCompressed.forEach(function (value, key) {
  if (!Number.isInteger(key) || value.length !== 32) {
    throw new Error("Bad key or value in compress label map in proofValue");
  }
})
if (!Array.isArray(mandatoryIndexes)) {
  throw new Error("mandatory indexes is not an array in proofValue");
}
mandatoryIndexes.forEach(value => {
  if (!Number.isInteger(value)) {
    throw new Error("Value in mandatory indexes  is not an integer");
  }
})
/* Replace the fourth element in components using the result of calling the algorithm in Section 3.4.6
  decompressLabelMap, passing the existing fourth element of components as compressedLabelMap.
*/
/* 3.4.6 decompressLabelMap
  The following algorithm decompresses a label map. The required input is a compressed label map
   (compressedLabelMap). The output is a decompressed label map.

    Initialize map to an empty map.
    For each entry (k, v) in compressedLabelMap:
        Add an entry to map with a key that adds the prefix "c14n" to k and a value
        that adds a prefix of "u" to the base64url-no-pad-encoded value for v.
    Return map as decompressed label map.
*/
let labelMap = new Map();
labelMapCompressed.forEach(function (v, k) {
  let key = "c14n" + k;
  let value = base64url.encode(v);
  labelMap.set(key, value);
})
// console.log(labelMap);
/* Return derived proof value as an object with properties set to the five elements, using the
  names "baseSignature", "publicKey", "signatures", "labelMap", and "mandatoryIndexes", respectively.*/
// Could use a test vector here
let derivedProofValue = {
  baseSignature: bytesToHex(baseSignature),
  publicKey: base58btc.encode(publicKey),
  signatures: signatures.map(sig => bytesToHex(sig)),
  labelMap: [...labelMap],
  mandatoryIndexes
}
// console.log(labelMap);
writeFile(baseDir + 'derivedProofValue.json', JSON.stringify(derivedProofValue, null, 2));

// Initialize labelMapFactoryFunction to the result of calling the "createLabelMapFunction" algorithm.
let labelMapFactoryFunction = await createLabelMapFunction({ labelMap });
/* Initialize nquads to the result of calling the "labelReplacementCanonicalize" algorithm, passing
  document, labelMapFactoryFunction, and any custom JSON-LD API options. Note: This step transforms
  the document into an array of canonical N-Quads with pseudorandom blank node identifiers based on
  labelMap.
*/
// async function labelReplacementCanonicalizeJsonLd({document, labelMapFactoryFunction, options} = {})
let nquads = await labelReplacementCanonicalizeJsonLd({
  document,
  labelMapFactoryFunction, options
});
// console.log(nquads);
writeFile(baseDir + 'verifyQuads.json', JSON.stringify(nquads, null, 2));
/*  Initialize mandatory to an empty array.
Initialize nonMandatory to an empty array.
For each entry (index, nq) in nquads, separate the N-Quads into mandatory and non-mandatory categories:

    If mandatoryIndexes includes index, add nq to mandatory.
    Otherwise, add nq to nonMandatory.
*/
let mandatory = [];
let nonMandatory = [];
nquads.forEach(function (value, index) {
  if (mandatoryIndexes.includes(index)) {
    mandatory.push(value);
  } else {
    nonMandatory.push(value);
  }
})
/*  Initialize mandatoryHash to the result of calling the "hashMandatory" primitive, passing mandatory.
Return an object with properties matching baseSignature, proofHash, publicKey, signatures,
nonMandatory, and mandatoryHash.
*/
// console.log("mandatory:");
// console.log(mandatory);
let te = new TextEncoder();
// **CAUTION** JavaScript join() without argument uses ',' comma!!!
let mandatoryHash = sha256(te.encode(mandatory.join('')));
// End of Create Verify Data ==> Create a test vector
let createVerifyData = {
  baseSignature: bytesToHex(baseSignature),
  proofHash: bytesToHex(proofHash),
  publicKey: base58btc.encode(publicKey),
  signatures: signatures.map(sig => bytesToHex(sig)),
  nonMandatory,
  mandatoryHash: bytesToHex(mandatoryHash)
};
writeFile(baseDir + 'createVerifyData.json', JSON.stringify(createVerifyData, null, 2));

/* If the length of signatures does not match the length of nonMandatory, throw an error
indicating that the signature count does not match the non-mandatory message count.
*/
if (signatures.length !== nonMandatory.length) {
  throw new Error("signature and nonMandatory counts do not match");
}
/* Initialize publicKeyBytes to the public key bytes expressed in publicKey. Instructions on
how to decode the public key value can be found in Section 2.1.1 Multikey.
**ISSUE**: Which public key? ==> non-ephemeral key from issuer
*/
// Get public key
console.log(proof.verificationMethod.split("did:key:"));
//
let encodedPbk = proof.verificationMethod.split("did:key:")[1].split("#")[0];
console.log(encodedPbk);
let pbk = base58btc.decode(encodedPbk);
pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);

/* Initialize toVerify to the result of calling the algorithm in Setion 3.4.1 serializeSignData,
passing proofHash, publicKey, and mandatoryHash.
*/

let toVerify = concatBytes(proofHash, publicKey, mandatoryHash);
// console.log(`toVerify length: ${toVerify.length}`);
// console.log("proof hash:");
// console.log(proofHash);
// console.log("public key:");
// console.log(publicKey);
// console.log("mandatoryHash:");
// console.log(mandatoryHash);

/* Initialize verificationResult be the result of applying the verification algorithm of the
Elliptic Curve Digital Signature Algorithm (ECDSA) [FIPS-186-5], with toVerify as the data to
be verified against the baseSignature using the public key specified by publicKeyBytes.
If verificationResult is false, return false.
*/

// Verify base signature
let msgHash = sha256(toVerify); // Hash is done outside of the algorithm in noble/curve case.
let verificationResult = p256.verify(baseSignature, msgHash, pbk);
console.log(`Base Signature verified: ${verificationResult}`);

/* For every entry (index, signature) in signatures, verify every signature for every
selectively disclosed (non-mandatory) statement:

    Initialize verificationResult to the result of applying the verification algorithm
    Elliptic Curve Digital Signature Algorithm (ECDSA) [FIPS-186-5], with the UTF-8
    representation of the value at index of nonMandatory as the data to be verified
    against signature using the public key specified by publicKeyBytes.
    If verificationResult is false, return false.

    **ISSUE**: this uses the ephemeral public key recovered from the CBOR encoding
    above and not the public key just used on the base signature.
*/

let ephemeralPubKey = publicKey.slice(2);
nonMandatory.forEach(function(quad, index) {
  let msgHash = sha256(quad); // Hash is done outside of the algorithm in noble/curve case.
  let sigVerified = p256.verify(signatures[index], msgHash, ephemeralPubKey);
  console.log(`Non Mandatory Signature ${index} verified: ${sigVerified}`);
  verificationResult &&= sigVerified;
})

console.log(`Derived document verified: ${verificationResult}`);