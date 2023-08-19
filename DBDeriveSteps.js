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

const options = {documentLoader: localLoader};

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
const proofValue = document.proof.proofValue; // base64url encoded
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
console.log(`proof publicKey: ${publicKey}`);
console.log(`mandatory pointers: ${mandatoryPointers}`);

// setup HMAC stuff
const hmac = await createHmac({key: hmacKey});
const labelMapFactoryFunction = createHmacIdLabelMapFunction({hmac});

// Combine pointers TODO: STOPPED HERE


// console.log(JSON.stringify(signedDocument, null, 2));
// writeFile(baseDir + 'signedSDBase.json', JSON.stringify(signedDocument, null, 2));


