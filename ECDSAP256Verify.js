/*
    Steps to verify a signed verifiable credential in the *DataIntegrityProof*
    representation with a "ecdsa-rdfc-2019" cryptosuite. Run this after
    ECDSAP256Create.js or modify to read in
    a signed file of your choice. Caveat: No error checking is performed.
*/
import { readFile } from 'fs/promises';
import { localLoader } from './documentLoader.js';
import jsonld from 'jsonld';
import { base58btc } from "multiformats/bases/base58";
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';

jsonld.documentLoader = localLoader;

const baseDir = "./output/ecdsa-rdfc-2019-p256/";
// Read signed input document from a file or just specify it right here.
const signedDocument = JSON.parse(
    await readFile(
      new URL(baseDir + 'signedECDSAP256.json', import.meta.url)
    )
  );

// Document without proof
let document = Object.assign({}, signedDocument);
delete document.proof;
console.log(document);

// Canonize the document
let cannon = await jsonld.canonize(document);
console.log("Canonized unsigned document:")
console.log(cannon);

// Hash canonized document
let docHash = sha256(cannon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized document in hex:")
console.log(bytesToHex(docHash));

// Set proof options per draft
let proofConfig = {};
proofConfig.type = signedDocument.proof.type;
proofConfig.cryptosuite = signedDocument.proof.cryptosuite;
proofConfig.created = signedDocument.proof.created;
proofConfig.verificationMethod = signedDocument.proof.verificationMethod;
proofConfig.proofPurpose = signedDocument.proof.proofPurpose;
proofConfig["@context"] = signedDocument["@context"]; // Missing from draft!!!

// canonize the proof config
let proofCanon = await jsonld.canonize(proofConfig);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);

// Hash canonized proof config
let proofHash = sha256(proofCanon); // @noble/hash will convert string to bytes via UTF-8
console.log("Hash of canonized proof in hex:")
console.log(bytesToHex(proofHash));

// Combine hashes
let combinedHash = concatBytes(proofHash, docHash); // Hash order different from draft

// Get public key
let encodedPbk = signedDocument.proof.verificationMethod.split("#")[1];
let pbk = base58btc.decode(encodedPbk);
pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);

// Verify
let msgHash = sha256(combinedHash); // Hash is done outside of the algorithm in noble/curve case.
let signature = base58btc.decode(signedDocument.proof.proofValue);
let result = p256.verify(signature, msgHash, pbk);
console.log(`Signature verified: ${result}`);
