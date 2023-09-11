# Test Vector Derivation for ECDSA-SD

This repository contains JavaScript (Node.js) code for the generation of test vectors for the ECDSA-SD (selective disclosure with ECDSA) Verifiable Credential Data Integrity specification, [VC-DI-ECDSA](https://w3c.github.io/vc-di-ecdsa/).

We will be using the specification, [DigitalBazaar: DI-SD-Primitives](https://github.com/digitalbazaar/di-sd-primitives), and my own code to come up with a consistent set of test vectors.

Notes:

* This effort is relatively new so code, example inputs, and generated test vectors are subject to change.
* As time progresses it is envisioned that I will implement more of the selective disclosure primitive functions and generate test vectors for those as well as ones already done for the key selective disclosure signature steps.
* Included are non-SD creation/verification files for reference: [ECDSAKeyCheck.js](ECDSA/ECDSAKeyCheck.js), [ECDSAP256Create.js](ECDSA/ECDSAP256Create.js) and [ECDSAP256Verify.js](ECDSA/ECDSAP256Verify.js).

## Implementation Notes

Libraries used:

* [@noble/hashes]() For hashes and HMAC
* [@noble/curves]() For signatures
* [jsonld]() for JSON-LD processing
* [multiformats](), [varint]() for Multiformat processing
* [klona](https://www.npmjs.com/package/klona) For deep cloning of arrays and objects
* [di-sd-primitives](https://github.com/digitalbazaar/di-sd-primitives/tree/main) Some of the processing is quite involved so will compare my implementations against this. Will use both to generate test vectors. Using NPM's [link](https://docs.npmjs.com/cli/v8/commands/npm-link) mechanism to tie to a locally built version of this. In this project use the command `npm link @digitalbazaar/di-sd-primitives` after running `npm link` within that project.

Libraries used to investigate stuff:

* [json-pointer](https://www.npmjs.com/package/json-pointer) To check that my example pointers are okay and select what I wanted.

## Raw Document and Mandatory Reveal

To produce the test vectors we need an input document, i.e., and unsigned verifiable credential. For this we use the file [windDoc.json](input/windDoc.json). Change this if you want to generate different examples, however you may also need to deal with JSON-LD document loading. See [documentLoader.js](./documentLoader.js) and the `contexts` directory. To indicate which parts of the document must be **mandatory* to reveal (from the issuer perspective) we use the array of JSON Pointers in the file [windMandatory.json](input/windMandatory.json).

## Add Base Proof Steps and Test Vectors

The code in [SDAddBaseSteps.js](./SDAddBaseSteps.js) produces a signed selective disclosure base proof, [addSignedSDBase.json](output/ecdsa-sd-2023/addSignedSDBase.json) and test vectors for intermediate steps. These are contained in the directory `output/ecdsa-sd-2023` and have files names prefixed with `add`.

## Derived Proof Steps and Test Vectors

The code in [SDDeriveSteps.js](./SDDeriveSteps.js) produces a selective disclosure derived proof, [deriveRevealDocument.json](output/ecdsa-sd-2023/derivedRevealDocument.json) and test vectors for intermediate steps. These are contained in the directory `output/ecdsa-sd-2023` and have files names prefixed with `derive`. It starts with the file [addSignedSDBase.json](output/ecdsa-sd-2023/addSignedSDBase.json).

## Verify Derived Proof Steps and Test Vectors

The code in [SDVerifyDeriveSteps.js](./SDVerifyDeriveSteps.js) verifies a selective disclosure derived document, and generates test vectors for intermediate steps. The test vectors are contained in the directory `output/ecdsa-sd-2023` and have files names prefixed with `verify`. It starts with the file [deriveRevealDocument.json](output/ecdsa-sd-2023/derivedRevealDocument.json).

# Test Vector Generation for SD-Primitives/BBS

It turns out that the selective disclosure primitives developed for ECDSA-SD are also applicable for use with BBS signatures. Although this is not yet part of a draft specification they following modification to the steps used in ECDSA-SD can produce BBS (selective disclosure signatures):

To come up with the BBS base proof we need:

1. Unsigned Document
2. HMAC Key
3. Mandatory Pointers
4. Use a concatenation of proofHash and mandatoryHash as input to the BBS *header*
5. Use the list of non-mandatory nquads as the BBS *messages*
6. Produce the BBS signature using the above *header* and *messages*
7. serialize via CBOR etc the following: BBSSignature, hmacKey, mandatoryPointers

To come up with the BBS Derived Proof we need:

1. BBSSignature (BBS proof input)
2. HMAC key
3. List of non-mandatory messages (BBS proof input)
4. Indexes of selective messages to be revealed (BBS proof input)
5. Need to recreate the header via proofConfig and mandatory disclosure stuff
6. Generate the BBSProofValue (output of BBS proof procedure)
7. serialize via CBOR: BBSProofValue, compressedLabelMap, mandatoryIndexes, selective indexes

See the directory `/BBS` for step by step code and test vectors.