/*
    Walking through the steps to  create a derived SD proof using Digital
    Bazaar SD-primitive functions.

    Reference:

    [Add Derived Proof (ecdsa-sd-2023)](https://pr-preview.s3.amazonaws.com/dlongley/vc-di-ecdsa/pull/27.html#add-derived-proof-ecdsa-sd-2023)

    Key steps:
    1. [createDisclosureData](https://pr-preview.s3.amazonaws.com/dlongley/vc-di-ecdsa/pull/27.html#createdisclosuredata)
    2. [serializeDerivedProofValue](https://pr-preview.s3.amazonaws.com/dlongley/vc-di-ecdsa/pull/27.html#serializederivedproofvalue)


*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import {
  createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup,
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

// Chosen to be tricky as mandatory has "/boards/0/year" but we are going to
// reveal all about board 0
const selectivePointers = ["/boards/0", "/boards/1"];

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

// Read base signed document from a file
let document = JSON.parse(
  await readFile(
    new URL(baseDir + 'signedSDBase.json', import.meta.url)
  )
);

const options = { documentLoader: localLoader };

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
const proof = document.proof;
delete document.proof; // IMPORTANT: all work uses document without proof
const proofValue = proof.proofValue; // base64url encoded
const proofValueBytes = base64url.decode(proofValue);
// console.log(proofValueBytes.length);
// check header bytes are: 0xd9, 0x5d, and 0x00
if (proofValueBytes[0] != 0xd9 || proofValueBytes[1] != 0x5d || proofValueBytes[2] != 0x00) {
  throw new Error("Invalid proofValue header");
}
let decodeThing = cbor.decode(proofValueBytes.slice(3));
if (decodeThing.length != 5) {
  throw new Error("Bad length of CBOR decoded proofValue data");
}
let [baseSignature, publicKey, hmacKey, signatures, mandatoryPointers] = decodeThing;
// console.log(`proof publicKey: ${publicKey}`);
// console.log(`mandatory pointers: ${mandatoryPointers}`);

// setup HMAC stuff
const hmac = await createHmac({ key: hmacKey });
const labelMapFactoryFunction = createHmacIdLabelMapFunction({ hmac });

// Combine pointers
const combinedPointers = mandatoryPointers.concat(selectivePointers);
/*
Initialize groupDefinitions to a map with the following entries: key of the string "mandatory"
and value of mandatoryPointers, key of the string "selective" and value of selectivePointers,
and key of the string "combined" and value of combinedPointers.
*/
const groups = {
  "mandatory": mandatoryPointers, "selective": selectivePointers,
  "combined": combinedPointers
};
let stuff = await canonicalizeAndGroup({
  document, labelMapFactoryFunction, groups,
  options
});
// console.log(stuff);
let combinedMatch = stuff.groups.combined.matching;
let mandatoryMatch = stuff.groups.mandatory.matching;
let selectiveMatch = stuff.groups.selective.matching;
let relativeIndex = 0;
let mandatoryIndexes = [];
/* For each absoluteIndex in the keys in groups.combined.matching, convert the absolute index
   of any mandatory N-Quad to an index relative to the combined output that is to be revealed:

    If groups.mandatory.matching has absoluteIndex as a key, then append relativeIndex to mandatoryIndexes.
    Increment relativeIndex.
*/
combinedMatch.forEach(function (value, absoluteIndex) {
  if (mandatoryMatch.has(absoluteIndex)) {
    mandatoryIndexes.push(relativeIndex);
  }
  relativeIndex++;
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

console.log(`size of signatures: ${signatures.length}`);
// console.log("mandatoryMatch:");
// console.log(mandatoryMatch);
// console.log("selectiveMatch:");
// console.log(selectiveMatch);
let index = 0;
const filteredSignatures = signatures.filter(() => {
  while (mandatoryMatch.has(index)) {
    index++;
  }
  return selectiveMatch.has(index++);
});
console.log(`Size of filteredSignatures: ${filteredSignatures.length}`);
// Initialize revealDocument to the result of the "selectJsonLd" algorithm,
// passing document, and combinedPointers as pointers.
// function selectJsonLd({document, pointers, includeTypes = true} = {})
let revealDocument = selectJsonLd({ document, pointers: combinedPointers}); // , includeTypes: true
// console.log(revealDocument);
/*
Run the RDF Dataset Canonicalization Algorithm [RDF-CANON] on the joined combinedGroup.deskolemizedNQuads,
passing any custom options, and get the canonical bnode identifier map, canonicalIdMap. Note: This map
includes the canonical blank node identifiers that a verifier will produce when they canonicalize the
reveal document.
*/
// Where/what is combinedGroup.dskolemizedNQuads?
// console.log(stuff.groups.combined);
let deskolemizedNQuads = stuff.groups.combined.deskolemizedNQuads;
let canonicalIdMap = new Map();
// The goal of the below is to get the canonicalIdMap and not the canonical document
await canonicalize(deskolemizedNQuads.join(''),
  { ...options, inputFormat: 'application/n-quads', canonicalIdMap });
// implementation-specific bnode prefix fix
canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap);
console.log(canonicalIdMap);
/* Initialize verifierLabelMap to an empty map. This map will map the canonical blank node identifiers
 the verifier will produce when they canonicalize the revealed document to the blank node identifiers
  that were originally signed in the base proof. (step 13)
*/
let verifierLabelMap = new Map();
/* For each key (inputLabel) and value (verifierLabel) in `canonicalIdMap:
    Add an entry to verifierLabelMap using verifierLabel as the key and the value associated with inputLabel
    as a key in labelMap as the value.
*/
// Need to get this from way back up there...
let labelMap = stuff.labelMap;
canonicalIdMap.forEach(function (value, key) {
  verifierLabelMap.set(value, labelMap.get(key));
});

  // DB code:
  // 9. Produce a blank node label map from the canonical blank node labels
  //   the verifier will see to the HMAC labels.
  // const verifierLabelMap = new Map();
  // for(const [inputLabel, verifierLabel] of canonicalIdMap) {
  //   verifierLabelMap.set(verifierLabel, labelMap.get(inputLabel));
  // }

//
// console.log(verifierLabelMap);
/* Return an object with properties matching baseSignature, publicKey, "signatures" for filteredSignatures,
"verifierLabelMap" for labelMap, mandatoryIndexes, and revealDocument.
  **End** of the *createDisclosureData* function
*/
let disclosureData = {
  baseSignature: bytesToHex(baseSignature), publicKey: base58btc.encode(publicKey),
  signatures: filteredSignatures.map(sig => bytesToHex(sig)),
  labelMap: [...verifierLabelMap],
  mandatoryIndexes,
  revealDocument
};
// console.log(JSON.stringify(disclosureData, null, 2));
writeFile(baseDir + 'disclosureData.json', JSON.stringify(disclosureData, null, 2));
// Initialize newProof to a shallow copy of proof.
let newProof = Object.assign({}, proof);
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
let compressLabelMap = new Map();
verifierLabelMap.forEach(function(v, k){
  let key = parseInt(k.split("c14n")[1]);
  let value = base64url.decode(v);
  compressLabelMap.set(key, value);
});
// console.log(compressLabelMap);
/*  Initialize a byte array, proofValue, that starts with the ECDSA-SD disclosure proof header
  bytes 0xd9, 0x5d, and 0x01.
  Initialize components to an array with five elements containing the values of: baseSignature,
  publicKey, signatures, compressedLabelMap, and mandatoryIndexes.
  CBOR-encode components and append it to proofValue.
  Return the derived proof as a string with the multibase-base64url-no-pad-encoding of proofValue.
  That is, return a string starting with "u" and ending with the base64url-no-pad-encoded value of proofValue.
*/
let derivedProofValue = new Uint8Array([0xd9, 0x5d, 0x01]);
let components = [baseSignature, publicKey, filteredSignatures, compressLabelMap, mandatoryIndexes];
let cborThing = await cbor.encodeAsync(components);
derivedProofValue = concatBytes(derivedProofValue, cborThing);
let derivedProofValueString = base64url.encode(derivedProofValue);
console.log(derivedProofValueString);
console.log(`Length of derivedProofValue is ${derivedProofValueString.length} characters`);
/*  Replace proofValue in newProof with the result of calling the algorithm in Section 3.4.7
  serializeDerivedProofValue, passing baseSignature, publicKey, signatures, labelMap, and mandatoryIndexes.
  Set the value of the "proof" property in revealDocument to newProof.
  Return revealDocument as the selectively revealed document. */
newProof.proofValue = derivedProofValueString;
revealDocument.proof = newProof;
// console.log(JSON.stringify(revealDocument, null, 2));
writeFile(baseDir + 'revealDocument.json', JSON.stringify(revealDocument, null, 2));

