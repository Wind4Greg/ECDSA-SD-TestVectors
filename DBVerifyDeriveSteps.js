/*
    Walking through the steps to verify a derived SD proof using Digital
    Bazaar SD-primitive functions.

    Reference:

    [3.5.7 Verify Derived Proof (ecdsa-sd-2023)](https://w3c.github.io/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023)

    Key initialization step: [3.4.9 createVerifyData](https://w3c.github.io/vc-di-ecdsa/#createverifydata)
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import {createLabelMapFunction, labelReplacementCanonicalizeJsonLd,
  canonicalizeAndGroup,
  selectJsonLd, canonicalize, stripBlankNodePrefixes
} from '@digitalbazaar/di-sd-primitives';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import { p256 } from '@noble/curves/p256';
import { klona } from 'klona';
import varint from 'varint';
import { base58btc } from "multiformats/bases/base58";
import cbor from "cbor";
import { base64url } from "multiformats/bases/base64";
import { bytes } from 'multiformats';

// Create output directory for the results
const baseDir = "./output/ecdsa-sd-2023/";
let status = await mkdir(baseDir, { recursive: true });

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

// Read base signed document from a file
let document = JSON.parse(
  await readFile(
    new URL(baseDir + 'DBderivedCredential.json', import.meta.url)
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
const proofValue = document.proof.proofValue;
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
/* **ISSUE** publicKey is currently in multi-key encoded form and not raw bytes. Spec did not say to
  use raw bytes in add proof or derive proof.
  ==> DB's code uses raw bytes. Will change my code. They have wrong key length.
*/
if (decodeThing.length != 5) {
  throw new Error("Bad length of CBOR decoded proofValue data");
}
let [baseSignature, publicKey, signatures, labelMapCompressed, mandatoryIndexes] = decodeThing;
// console.log(baseSignature, typeof baseSignature);
if (!baseSignature.BYTES_PER_ELEMENT === 1 && baseSignature.length === 64) {
  throw new Error("Bad baseSignature in proofValue");
}
console.log(`publicKey: ${bytesToHex(publicKey)}`);
console.log(`publicKey length: ${publicKey.length}`);
// let publicKeyBytes = base58btc.decode(publicKey);
// publicKeyBytes = publicKeyBytes.slice(2, publicKeyBytes.length); // First two bytes are multi-format indicator
// console.log(`Public Key hex: ${bytesToHex(publicKeyBytes)}, Length: ${publicKeyBytes.length}`);
if (!Array.isArray(signatures)) {
  throw new Error("signatures in proof value is not an array");
}
signatures.forEach(function(value){
  if (!value.BYTES_PER_ELEMENT === 1 && value.length === 64) {
    throw new Error("Bad signature in signatures array in proofValue");
  }
})
if (!labelMapCompressed instanceof Map) {
  throw new Error("Bad label map in proofValue");
}
labelMapCompressed.forEach(function(value, key) {
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
labelMapCompressed.forEach(function(v, k) {
  let key = "c14n" + k;
  let value = base64url.encode(v);
  labelMap.set(key, value);
})
// console.log(labelMap);
/* Return derived proof value as an object with properties set to the five elements, using the
  names "baseSignature", "publicKey", "signatures", "labelMap", and "mandatoryIndexes", respectively.*/
// Could use a test vector here
let derivedProofValue = { baseSignature: bytesToHex(baseSignature),
  publicKey,
  signatures: signatures.map(sig => bytesToHex(sig)),
  labelMap: [...labelMap],
  mandatoryIndexes
}
console.log(labelMap);
/*
Map(5) {
  'c14n0' => 'u6i_pt_uhM5j8KYmPPuIyFbjnLpeuM4oLoNC_c-VnUCw',
  'c14n1' => 'uhEPZucmqaRiNUuY9C7wpl92P3odrK7c-MRnUBh3P0Aw',
  'c14n2' => 'uQ7WMgN7TDEZCoqcDsMjr48_dgUKxSzfSD3DUkAuhMpw',
  'c14n3' => 'u_7bWKzi7k-tAtKgsCOdLsp6maOxmhf7ND6ITBKKeoU8',
  'c14n4' => 'uY0YIS2SugLXL1SwfOM0rIvP3UDcKTQmAvV64_FpdYJw'
}
*/
writeFile(baseDir + 'derivedProofValue.json', JSON.stringify(derivedProofValue, null, 2));

// Initialize labelMapFactoryFunction to the result of calling the "createLabelMapFunction" algorithm.
let labelMapFactoryFunction = await createLabelMapFunction({labelMap});
/* Initialize nquads to the result of calling the "labelReplacementCanonicalize" algorithm, passing
  document, labelMapFactoryFunction, and any custom JSON-LD API options. Note: This step transforms
  the document into an array of canonical N-Quads with pseudorandom blank node identifiers based on
  labelMap.
*/
// async function labelReplacementCanonicalizeJsonLd({document, labelMapFactoryFunction, options} = {})
let nquads = await labelReplacementCanonicalizeJsonLd({document,
  labelMapFactoryFunction, options});
console.log(nquads);
writeFile(baseDir + 'verifyQuads.json', JSON.stringify(nquads, null, 2));
 console.log("document:");
 console.log(document);