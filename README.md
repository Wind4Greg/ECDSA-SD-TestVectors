---
author: Dr. Greg M. Bernstein
date: 2023-08-06
title: Selective Disclosure for ECDSA -- Test Vectors
---

# Test Vector Derivation for ECDSA-SD

This repository contains JavaScript (Node.js) code for the generation of test vectors for the ECDSA-SD (selective disclosure with ECDSA) Verifiable Credential Data Integrity specification, [VC-DI-ECDSA](https://w3c.github.io/vc-di-ecdsa/).

We will be using the specification, [DigitalBazaar: DI-SD-Primitives](https://github.com/digitalbazaar/di-sd-primitives), and my own code to come up with a consistent set of test vectors.

Notes:

* This effort is just starting so things are in very **rough** shape
* Included are non-SD creation/verification files for reference: `ECDSAP256Create.js` and `ECDSAP256Verify.js`.

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

# Add Base Proof Steps and Vectors

From the specification the main steps for an issuer to create the *base proof* from which a holder can created selectively disclosed *derived proof* are:

1. Base Proof Transformation (ecdsa-sd-2023)
2. Base Proof Hashing (ecdsa-sd-2023)
3. Base Proof Serialization (ecdsa-sd-2023)

Our code produces test vectors for these steps and for important intermediate results.

## Raw Document and Mandatory Reveal

To start things off need an unsigned document and a list of mandatory reveal JSON pointers.
See `input/windDoc.json` shown below along with the pointers. This is loosely based on the
idea of registering equipment prior to a windsurfing race.

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2",
    {"@vocab": "https://windsurf.grotto-networking.com/selective#"}],
  "type": ["VerifiableCredential"],
  "sailNumber": "Earth101",
  "sails": [
    {"size": 5.5, "sailName": "Osprey", "year": 2023},
    {"size": 6.1, "sailName": "Eagle-FR", "year": 2023},
    {"size": 7.0, "sailName": "Eagle-FR", "year": 2020},
    {"size": 7.8, "sailName": "Eagle-FR", "year": 2023 }],
  "boards": [
    {"boardName": "CompFoil170", "brand": "Tillo", "year": 2022},
    {"boardName": "Tillo Custom", "brand": "Tillo", "year": 2019}]
}
```

Mandatory reveal JSON pointers indicate what information must be revealed (this
comes from the issuer). The following forces the disclosure of the sail number, two of the
sails and the year of one of the boards.

```json
["/sailNumber", "/sails/1", "/boards/0/year", "/sails/2"]
```

## Transformed Document

The file `output/addBaseTransform.json` is show below. The *mandatory* and *nonMandatory* attributes are actually `Maps` that have been converted into arrays of pairs for output purposes. In addition the `hmacKey` is given as a hexadecimal string.

```json
{
  "mandatoryPointers": ["/sailNumber", "/sails/1", "/boards/0/year", "/sails/2"],
  "mandatory": [
    [0, "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sailName> \"Eagle-FR\" .\n"],
    [1,       "_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n"],
    "... more stuff removed"
  ],
  "nonMandatory": [
    [3, "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#sailName> \"Osprey\" .\n"],
    [4, "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n"],
    "... more stuff removed"
  ],
  "hmacKeyString": "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
}
```

## Create and Canonize the Proof Options

This step is the RDF canonicalization of the proof options. File: `proofConfigCanonECDSA_SD.txt`.

```text
_:c14n0 <http://purl.org/dc/terms/created> "2023-08-15T23:36:38Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:c14n0 <https://w3id.org/security#cryptosuite> "ecdsa-rdfc-2019" .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <https://vc.example/issuers/5679#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP> .
```

## Hashing

The hashed data which includes the transformed data looks like, i.e., adds hashes for the `proofConfig` and the *mandatory* reveal data.

```json
{
  "mandatoryPointers": ["already shown"],
  "mandatory": ["already shown"],
  "nonMandatory": ["already shown"],
  "hmacKeyString": "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
  "proofHash": "cbbb2845046705baed3a6c73a6ce86249f135b7e310ed1c694e8b3fd72ab8516",
  "mandatoryHash": "de48264d44054d254a7ce8b01fe30786b8e71e7034075e4aba1c887714c6bae6"
}
```

## Base Proof Serialization

This is actually two steps: (a) signing, and (b) serialization. The information produce by signing looks like `rawBaseSignatureInfo.json`:

```json
{
  "baseSignature": "c840b40404cc8b9e50f94a44373f5b820471f3f4a413bf18998787dc759cfce7488c2828909ba8e8aabb1d80ef966ab857fa6f2e0b44075e358a60927461ebac",
  "publicKey": "zDnaeTHfhmSaQKBc7CmdL3K7oYg3D6SC7yowe2eBeVd2DH32r",
  "signatures": [
    "b1194e4592a880414847434522f91dac9d15e57cc97e9fdae9db45b36132e22815204bb009c2e9a82718482e74212e115fc3dcbc4c641b45221d9163355d16fb",
    "5b4b8b22ad027a61b0e0314cc009c6cc1c7ebd98275457e5e12193778dbdb7255948fdf5185f48b56f8adbacb413aca4b1f18d1344700fa19b74764ea9b35ae9",
    "4ed3306442fdd1eadd783b572fc8ac4139f3d088f8d56dcec784fe1e31a2ae3a361fc428032c938972c099cc563d440695cda4aa7a9bd46c34cd6495b6d7cc9b",
    "8a90f7ec7c1230976639d9e43a467a7bbe2bccd03152526a303e2c0556deed9574e3fbc1f9b37e39be8a46056f5047637e67576a4c621ab9c342ccbfc62c7689",
    "0ffeb7009fad6f7a9c1a375a68e0b3831fa1c593f8eccfe8d8ca162bd64f39ee00dca831211b930fe0f724e6796bc5f9ac3cf993a92871b30515ba5c1d0d1174",
    "b51cd241db4dcabc6bc9316aad8b84d1faaccb564917d3761eb6a85b59b8a5e198d47f997adda7cfa1ac61deb5dad6514c335121e42ed1b3f32cff87b4794e21",
    "66317e8f3aa093b0024b94615664e6ef8b74c57fc1fdb1b44bd6c68c791d7b72274148974c1cbc2b2f638283793385e409d66b90ca5e0de84e218388a24504c5",
    "3f6842d33162f2b67b7997af0ad8dcec5efc9b8376aaa23feef40d818fb4f1fd312cf97225ee98d4b09fb7b97b82a9d2467d419bfbb702591d264b14457ccb42",
    "78f5f79c389db480356242250a1e55d639bb3b9d93903ab5c90f55a53747e2e1cc87dd5d715651dfdf27245609f08f86fddf3e0e6768ca545024c20314877b2b",
    "0e3d249105f519556a615b093aebfe147fe60e18ba8678401b2989a8bef343bcf245ee635216371d9fbc01e3c7d2767e16dcc4302828a0f6cda31032e2f346c2",
    "6112e746b34dcf9726979be03d956efc0f524d0a9c04cc3d6e7c0bda41e5ab113784434fb9a799992cf322e347a9a668023bda7f1f54248ed5dfcd931e4445be",
    "9e76ad4e62bafab3470f7be6d92ca88a4876df8b0784c66a1ddbafefd7781315ca2452eb03f7220d65bdac13f33901e6c5188ba7f713645f2206010fa6d1f205",
    "7a12a394f1503b0b7a1b9e2995ca0d78bb1efeba6ef98597c0abd229b4c91c159469624ebab3b59cc420e28796a7921d6d9beee19271c6b1d604895a3a574a5e",
    "9ba4c197083703da56c811f33829a96537d2ea85848ec3c4c1067de6387fd96e2ee9e9058cb256b502a0450933798ce3a54a4dcf72038546c1b9c735514b2b68"
  ],
  "mandatoryPointers": ["/sailNumber", "/sails/1", "/boards/0/year", "/sails/2"]
}
```

The result of the serialization step gets put into the final signed base document:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2",
    {"@vocab": "https://windsurf.grotto-networking.com/selective#"}],
  "type": ["VerifiableCredential"],
  "sailNumber": "Earth101",
  "sails": [
    {"size": 5.5, "sailName": "Osprey", "year": 2023},
    {"size": 6.1, "sailName": "Eagle-FR", "year": 2023},
    {"size": 7.0, "sailName": "Eagle-FR", "year": 2020},
    {"size": 7.8, "sailName": "Eagle-FR", "year": 2023 }],
  "boards": [
    {"boardName": "CompFoil170", "brand": "Tillo", "year": 2022},
    {"boardName": "Tillo Custom", "brand": "Tillo", "year": 2019}],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-rdfc-2019",
    "created": "2023-08-15T23:36:38Z",
    "verificationMethod": "https://vc.example/issuers/5679#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
    "proofPurpose": "assertionMethod",
    "proofValue": "u2V0AhdhAWEDIQLQEBMyLnlD5SkQ3P1uCBHHz9KQTvxiZh4fcdZz850iMKCiQm6joqrsdgO-WarhX-m8uC0QHXjWKYJJ0YeuseDF6RG5hZVRIZmhtU2FRS0JjN0NtZEwzSzdvWWczRDZTQzd5b3dlMmVCZVZkMkRIMzJy2EBYIAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7_jthAWECxGU5FkqiAQUhHQ0Ui-R2snRXlfMl-n9rp20WzYTLiKBUgS7AJwumoJxhILnQhLhFfw9y8TGQbRSIdkWM1XRb72EBYQFtLiyKtAnphsOAxTMAJxswcfr2YJ1RX5eEhk3eNvbclWUj99RhfSLVvitustBOspLHxjRNEcA-hm3R2TqmzWunYQFhATtMwZEL90erdeDtXL8isQTnz0Ij41W3Ox4T-HjGirjo2H8QoAyyTiXLAmcxWPUQGlc2kqnqb1Gw0zWSVttfMm9hAWECKkPfsfBIwl2Y52eQ6Rnp7vivM0DFSUmowPiwFVt7tlXTj-8H5s345vopGBW9QR2N-Z1dqTGIaucNCzL_GLHaJ2EBYQA_-twCfrW96nBo3Wmjgs4MfocWT-OzP6NjKFivWTznuANyoMSEbkw_g9yTmeWvF-aw8-ZOpKHGzBRW6XB0NEXTYQFhAtRzSQdtNyrxryTFqrYuE0fqsy1ZJF9N2HraoW1m4peGY1H-Zet2nz6GsYd612tZRTDNRIeQu0bPzLP-HtHlOIdhAWEBmMX6POqCTsAJLlGFWZObvi3TFf8H9sbRL1saMeR17cidBSJdMHLwrL2OCg3kzheQJ1muQyl4N6E4hg4iiRQTF2EBYQD9oQtMxYvK2e3mXrwrY3Oxe_JuDdqqiP-70DYGPtPH9MSz5ciXumNSwn7e5e4Kp0kZ9QZv7twJZHSZLFEV8y0LYQFhAePX3nDidtIA1YkIlCh5V1jm7O52TkDq1yQ9VpTdH4uHMh91dcVZR398nJFYJ8I-G_d8-DmdoylRQJMIDFId7K9hAWEAOPSSRBfUZVWphWwk66_4Uf-YOGLqGeEAbKYmovvNDvPJF7mNSFjcdn7wB48fSdn4W3MQwKCig9s2jEDLi80bC2EBYQGES50azTc-XJpeb4D2VbvwPUk0KnATMPW58C9pB5asRN4RDT7mnmZks8yLjR6mmaAI72n8fVCSO1d_Nkx5ERb7YQFhAnnatTmK6-rNHD3vm2Syoikh234sHhMZqHduv79d4ExXKJFLrA_ciDWW9rBPzOQHmxRiLp_cTZF8iBgEPptHyBdhAWEB6EqOU8VA7C3obnimVyg14ux7-um75hZfAq9IptMkcFZRpYk66s7WcxCDih5ankh1tm-7hknHGsdYEiVo6V0pe2EBYQJukwZcINwPaVsgR8zgpqWU30uqFhI7DxMEGfeY4f9luLunpBYyyVrUCoEUJM3mM46VKTc9yA4VGwbnHNVFLK2iEay9zYWlsTnVtYmVyaC9zYWlscy8xbi9ib2FyZHMvMC95ZWFyaC9zYWlscy8y"
  }
}
```

# Add Derived Proof

The holder selects what to reveal via JSON pointers.

```javascript
// Chosen to be tricky as mandatory has "/boards/0/year" but we are going to
// reveal all about board 0
const selectivePointers = ["/boards/0", "/boards/1"];
```

## Create Disclosure Data

Create data to be used to generate a derived proof. Byte arrays are represented by
hexadecimal strings:

```json
{
  "baseSignature": "c840b40404cc8b9e50f94a44373f5b820471f3f4a413bf18998787dc759cfce7488c2828909ba8e8aabb1d80ef966ab857fa6f2e0b44075e358a60927461ebac",
  "publicKey": "zDnaeTHfhmSaQKBc7CmdL3K7oYg3D6SC7yowe2eBeVd2DH32r",
  "signatures": [
    "b1194e4592a880414847434522f91dac9d15e57cc97e9fdae9db45b36132e22815204bb009c2e9a82718482e74212e115fc3dcbc4c641b45221d9163355d16fb",
    "5b4b8b22ad027a61b0e0314cc009c6cc1c7ebd98275457e5e12193778dbdb7255948fdf5185f48b56f8adbacb413aca4b1f18d1344700fa19b74764ea9b35ae9",
    "4ed3306442fdd1eadd783b572fc8ac4139f3d088f8d56dcec784fe1e31a2ae3a361fc428032c938972c099cc563d440695cda4aa7a9bd46c34cd6495b6d7cc9b",
    "0ffeb7009fad6f7a9c1a375a68e0b3831fa1c593f8eccfe8d8ca162bd64f39ee00dca831211b930fe0f724e6796bc5f9ac3cf993a92871b30515ba5c1d0d1174"
  ],
  "labelMap": [
    ["c14n0", "u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg"],
    ["c14n1", "uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw"],
    ["c14n2", "ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc"],
    ["c14n3", "uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk"],
    ["c14n4", "u2IE-HtO6PyHQsGnuqhO1mX6V7RkRREhF0d0sWZlxNOY"] ],
  "mandatoryIndexes": [3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17],
  "revealDocument": {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      {"@vocab": "https://windsurf.grotto-networking.com/selective#"}],
    "type": ["VerifiableCredential"],
    "sailNumber": "Earth101",
    "sails": [
      {"size": 6.1, "sailName": "Eagle-FR", "year": 2023},
      {"size": 7, "sailName": "Eagle-FR", "year": 2020} ],
    "boards": [
      {"year": 2022, "boardName": "CompFoil170", "brand": "Tillo"},
      {"boardName": "Tillo Custom", "brand": "Tillo", "year": 2019}]
  }
}
```

## Serialize Derived Proof, Signed Selective Reveal

In this step we serialize the derived proof and produced the signed selective reveal document:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    {
      "@vocab": "https://windsurf.grotto-networking.com/selective#"
    }
  ],
  "type": [
    "VerifiableCredential"
  ],
  "sailNumber": "Earth101",
  "sails": [
    {
      "size": 6.1,
      "sailName": "Eagle-FR",
      "year": 2023
    },
    {
      "size": 7,
      "sailName": "Eagle-FR",
      "year": 2020
    }
  ],
  "boards": [
    {
      "year": 2022,
      "boardName": "CompFoil170",
      "brand": "Tillo"
    },
    {
      "boardName": "Tillo Custom",
      "brand": "Tillo",
      "year": 2019
    }
  ],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-rdfc-2019",
    "created": "2023-08-15T23:36:38Z",
    "verificationMethod": "https://vc.example/issuers/5679#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
    "proofPurpose": "assertionMethod",
    "proofValue": "u2V0BhdhAWEDIQLQEBMyLnlD5SkQ3P1uCBHHz9KQTvxiZh4fcdZz850iMKCiQm6joqrsdgO-WarhX-m8uC0QHXjWKYJJ0YeuseDF6RG5hZVRIZmhtU2FRS0JjN0NtZEwzSzdvWWczRDZTQzd5b3dlMmVCZVZkMkRIMzJyhNhAWECxGU5FkqiAQUhHQ0Ui-R2snRXlfMl-n9rp20WzYTLiKBUgS7AJwumoJxhILnQhLhFfw9y8TGQbRSIdkWM1XRb72EBYQFtLiyKtAnphsOAxTMAJxswcfr2YJ1RX5eEhk3eNvbclWUj99RhfSLVvitustBOspLHxjRNEcA-hm3R2TqmzWunYQFhATtMwZEL90erdeDtXL8isQTnz0Ij41W3Ox4T-HjGirjo2H8QoAyyTiXLAmcxWPUQGlc2kqnqb1Gw0zWSVttfMm9hAWEAP_rcAn61vepwaN1po4LODH6HFk_jsz-jYyhYr1k857gDcqDEhG5MP4Pck5nlrxfmsPPmTqShxswUVulwdDRF0pQDYQFgg3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHgB2EBYIFZFLga5TmhCxlUFiQ-DP6luW3ChB1hjWzqzwP6gDiisAthAWCCRHb33UYm7L9OSN6b_HuktWlLgLgaRkBy4a2I-EF9JJwPYQFggk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDkE2EBYINiBPh7Tuj8h0LBp7qoTtZl-le0ZEURIRdHdLFmZcTTmhGsvc2FpbE51bWJlcmgvc2FpbHMvMW4vYm9hcmRzLzAveWVhcmgvc2FpbHMvMg"
  }
}
```

# Assorted Notes

**Very rough** subject to removal...

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

## Unsecured Document Example 1: Windsurf Racing

See `input/windDoc`. It is mandatory that the sail number be revealed. In addition one board and one sail must be revealed.

Setting up mandatory pointers. See [JSON Pointers RFC6901](https://datatracker.ietf.org/doc/html/rfc6901)
