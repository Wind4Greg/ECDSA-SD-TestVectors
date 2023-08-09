---
author: Dr. Greg M. Bernstein
date: 2023-08-6
title: Selective Disclosure for ECDSA -- Test Vectors
---

# Test Vector Derivation for ECDSA-SD

This repository contains JavaScript (Node.js) code for the generation of test vectors for the ECDSA-SD (selective disclosure with ECDSA) Verifiable Credential Data Integrity specification, [VC-DI-ECDSA](https://w3c.github.io/vc-di-ecdsa/).

For an alternative implementation see: [DigitalBazaar: ECDSA-SD-2023](https://github.com/digitalbazaar/ecdsa-sd-2023-cryptosuite) and [DigitalBazaar: DI-SD-Primitives](https://github.com/digitalbazaar/di-sd-primitives).

## Implementation Notes

Libraries used:

* [@noble/hashes]() For hashes and HMAC
* [@noble/curves]() For signatures
* [jsonld]() for JSON-LD processing
* [multiformats](), [varint]() for Multiformat processing
* [klona](https://www.npmjs.com/package/klona) For deep cloning of arrays and objects

Libraries used to investigate stuff:

* [json-pointer](https://www.npmjs.com/package/json-pointer) To check that my example pointers are okay and select what I wanted.

## Add Base Proof

Fixed inputs: *cryptosuite*, *key pair* (which includes curve choice P-256 or P-384)

Overall inputs:

* unsecured data document (unsecuredDocument) and transformation options (options).
* an array of mandatory JSON pointers (mandatoryPointers)

This consists of the following documented steps:

1. Base Proof Transformation (ecdsa-sd-2023)
2. Base Proof Hashing (ecdsa-sd-2023)
3. Base Proof Serialization (ecdsa-sd-2023)

### Proof Transformation

Takes the unsecured document canonizes it with JSON-LD RDFC; Blank node values are obscured via an HMAC; JSON-LD frame processing is used along with the input array of mandatory pointers to separate the N-quads into mandatory and non-mandatory groupings.

Returns

```javascript
{
    mandatoryPointers: [], // array of mandatory N-quads
    nonMandatory: [],  //
    hmacKey: "001122ddffee" // will use hex for examples and convert to Uint8Array for use with HMAC library
}
```

See [@noble/hash HMAC](https://www.npmjs.com/package/@noble/hashes#hmac)

**How to map blank node ids**:

From the [RDF canonicalization spec](https://www.w3.org/TR/rdf-canon/#canon-terms):

> A blank node identifier as specified by [RDF11-CONCEPTS]. In short, it is a string that begins with _: that is used as an identifier for a blank node. Blank node identifiers are typically implementation-specific local identifiers; this document specifies an algorithm for deterministically specifying them.
>
> Concrete syntaxes, like [Turtle] or [N-Quads], prepend blank node identifiers with the _: string to differentiate them from other nodes in the graph. This affects the canonicalization algorithm, which is based on calculating a hash over the representations of quads in this format.

Here's the regex that [Mattr](https://github.com/mattrglobal/jsonld-signatures-bbs/blob/cd936ea71a871633ddead4f91a0e2de1c0ed82cc/src/BbsBlsSignatureProof2020.ts#L127-L158) used `(/(_:c14n[0-9]+)/g` and here is information on [JavaScript string replace function](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace)

### JSON-LD Framing

Reference [JSON-LD Framing](https://json-ld.org/spec/FCGS/json-ld-framing/20180607/#introduction)

> Frame: A JSON-LD document, which describes the form for transforming another JSON-LD document using matching and embedding rules. A frame document allows additional keywords and certain property values to describe the matching and transforming process.
> frame object: A frame object is a dictionary element within a frame which represents a specific portion of the frame matching either a node object or a value object in the input.

From the `strictFrame` function description: "Set framedDocument to the result of the JSON-LD Framing algorithm, passing document and frame, and setting the options requireAll, explicit, and omitGraph to true. "

## Verify Base Proof

*Note*: this step currently missing from the specification.

## Add Derived Proof

## Verify Derived Proof

## Unsecured Document Example 1: Windsurf Racing

See `input/windDoc`. It is mandatory that the sail number be revealed. In addition one board and one sail must be revealed.

Setting up mandatory pointers. See [JSON Pointers RFC6901](https://datatracker.ietf.org/doc/html/rfc6901)

## Temp stuff

```
{
  "@requireAll": true,
  "@explicit": true,
  "@omitGraph": true,
  "type": [
    "VerifiableCredential"
  ],
  "sailNumber": {
    "0": "E",
    "1": "a",
    "2": "r",
    "3": "t",
    "4": "h",
    "5": "1",
    "6": "0",
    "7": "1"
  },
  "sails": [
    null,
    {
      "size": 6.1,
      "name": "Eagle-FR",
      "year": 2023
    }
  ],
  "boards": [
    {
      "year": {}
    }
  ],
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
    {
      "@vocab": "https://windsurf.grotto-networking.com/selective#"
    }
  ]
}
```