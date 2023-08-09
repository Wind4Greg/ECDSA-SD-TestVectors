/*
    Rough start of ECDSA-SD Add base test vector creation based on curve P-256.
    As we go along we will probably pull out functions into a separate file...

    DO NOT USE YET!!!

*/

import { readFile, writeFile } from 'fs/promises';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { base58btc } from "multiformats/bases/base58";
import { base64url} from "multiformats/bases/base64";
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import {klona} from 'klona';

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

const keyPair = {
    publicKeyMultibase: "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
};


let privateKey = hexToBytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
let publicKey = p256.getPublicKey(privateKey);

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL('./input/windDoc.json', import.meta.url)
    )
  );

// Signed Document Creation Steps:

// Canonize the document
let cannon = await jsonld.canonize(document);
console.log("Canonized unsigned document:")
console.log(cannon);
writeFile('./output/canonDocECDSA-SD.txt', cannon);

// Replace blank node ids with HMAC based ids
// Need an HMAC string
let hmacKeyString = '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF';
let hmacKey = hexToBytes(hmacKeyString);
console.log(hmacKey.length);
let bnodeIdMap = new Map(); // Keeps track of old blank node ids and their replacements

// HMAC based bnode replacement function
function hmacID(bnode) {
  let label = bnode.slice(2);
  if (bnodeIdMap.has(label)) {
    return bnodeIdMap.get(label)
  }
  let hmacBytes = hmac(sha256, hmacKey, label);
  let newId = '_:' + base64url.encode(hmacBytes);
  bnodeIdMap.set(label, newId);
  return newId;
}

// Using JavaScripts string replace with global regex and above replacement function
let hmacQuads = cannon.replace(/(_:c14n[0-9]+)/g, hmacID);

console.log(hmacQuads);
console.log(bnodeIdMap);

// Try producing list like they did
let hmacQuadArray = hmacQuads.split('\n').slice(0, -1).sort();
console.log(hmacQuadArray); // Identical to theirs except for CR at the end of each element of array.


// Need to set up mandatory pointers and pointers to frame stuff
// 3.4.10 jsonPointersToFrame
// example pointers:
const pointers = ["/sailNumber", "/sails/1"];
// Initialize frame to an initial frame passing document as value to the algorithm in Section 3.4.9 createInitialFrame.

// 3.4.9 createInitialFrame
// The following algorithm creates an initial JSON-LD frame based on a JSON-LD object.
// This is a helper function used within the algorithm in Section 3.4.10 jsonPointersToFrame.
// The required input is a JSON-LD object (value). A JSON-LD frame frame is produced as output.
// Initialize frame to an empty object.
// If value has an id that is not a blank node identifier, set frame.id to its value.
// Note: All non-blank node identifiers in the path of any JSON Pointer MUST be included in the frame,
// this includes any root document identifier.
// If value.type is set, set frame.type to its value. Note: All types in the path
// of any JSON Pointer MUST be included in the frame, this includes any root document type.
// Return frame.
function createInitialFrame(value) {
  let frame = {};
  if (typeof value !== "object") {
    return frame;
  }
  if ("id" in value) {
    // TODO: check if blank node identifier, if it is don't assign
    frame.id = value.id;
  }
  if ("type" in value) {
    frame.type = value.type;
  }
  return frame;
}

let frame = createInitialFrame(document);
// console.log(frame);

pointers.forEach(function(pointer){
  //  Initialize parentFrame to frame.
  let parentFrame = frame;
  let parentValue = document;
  let value = parentValue;
  let valueFrame = parentFrame;
  // Parse the pointer into an array of paths using the algorithm in Section 3.4.8 jsonPointerToPaths.
  let paths = jsonPointerToPaths(pointer);
  // console.log(pointer, paths);
  //  For each path in paths:
  paths.forEach(function(path){
    parentFrame = valueFrame;
    parentValue = value;
    // Set value to parentValue[path]. If value is now undefined, throw an error
    // indicating that the JSON pointer does not match the given document.
    value = parentValue[path];
    if (value === undefined) {
      throw new Error(`JSON Pointer ${pointer} does not match the document!`);
    }
    valueFrame = parentFrame[path];
    // If valueFrame is undefined:
    if (typeof valueFrame === 'undefined') {
      if (Array.isArray(value)) {
        valueFrame = [];
      } else {
        valueFrame = createInitialFrame(value);
      }
      parentFrame[path] = valueFrame;
    }
  })

  // Note: Next we generate the final valueFrame.
  // If value is not an object, then a literal has been selected: Set valueFrame to value.
  if (typeof value !== 'object') {
    valueFrame = value;
  }
  // Otherwise, if value is an array: Set valueFrame to the result of mapping every element
  // in value to a deep copy of itself. If any element in value is also an array, throw an error
  // indicating that arrays of arrays are not supported.
  if (Array.isArray(value)) {
    // TODO check for arrays in arrays
    valueFrame = value.map(e => klona(e));
  }
  // Otherwise: Set valueFrame to an object that merges a shallow copy of valueFrame with a deep copy of
  //value, e.g., {...valueFrame, …deepCopy(value)}.
  valueFrame = {...valueFrame, ...klona(value)};
  // If paths has a length of zero, then the whole document has been selected by the pointer: Set frame to valueFrame.
  if (paths.length === 0) {
    frame = valueFrame;
  } else {
  // Otherwise, a partial selection has been made by the pointer:
  //     Get the last path, lastPath, from paths.
  //     Set parentFrame[lastPath] to valueFrame.
    let lastPath = paths[paths.length-1];
    parentFrame[lastPath] = valueFrame;
  }
})
// console.log(value);
// console.log(valueFrame);

// Set frame['@context'] to a deep copy of document['@context'].
frame['@context'] = klona(document['@context']);
console.log("\nCreated Frame:");
console.log(JSON.stringify(frame, null, 2));
// Return frame.
// Try using the frame
const FRAME_FLAGS = {
  requireAll: true,
  explicit: true,
  omitGraph: true
};
const test = await jsonld.frame(document, frame, FRAME_FLAGS);
let skolQuads = skolemize(hmacQuads.split("\n"));
skolQuads = skolQuads.join("\n");
let hmacQuad2Doc = await jsonld.fromRDF(skolQuads, {format: 'application/n-quads'})
// console.log(hmacQuad2Doc);
const test2 = await jsonld.frame(hmacQuad2Doc, frame, FRAME_FLAGS);
// console.log(test);
// console.log(JSON.stringify(test2, null, 2));

// 3.4.8 jsonPointerToPaths
// The following algorithm converts a JSON Pointer [RFC6901] to an array of paths
// into a JSON tree. The required input is a JSON Pointer string (pointer). An array
// of paths (paths) is produced as output.
//
function jsonPointerToPaths(pointer) {
  // Initialize splitPath to an array by splitting pointer on the "/" character and
  // skipping the first, empty, split element. In Javascript notation, this step is
  // equivalent to the following code: pointer.split('/').slice(1)
  let splitPath = pointer.split('/').slice(1);
  let paths = [];
  splitPath.forEach(function(path) {
    // For each path in splitPath:
    //     If path does not include ~, then add path to paths, converting it to an integer
    //     if it parses as one, leaving it as a string if it does not.
    //     Otherwise, unescape any JSON pointer escape sequences in path and add the result to paths.
    if (path.includes("~")) {
      // TODO: JSON Pointer escape sequence
    } else {
      // check if it is an integer
      if(isInteger(path)) {
        paths.push(parseInt(path));
      } else {
        paths.push(path);
      }
    }
  });
  return paths;
}

function isInteger(value) { // From StackOverflow
  return /^\d+$/.test(value);
}

// Modified from DB temporarily
function skolemize(nquads) {
  const mutated = [];
  for(const nq of nquads) {
    if(!nq.includes('_:')) {
      mutated.push(nq);
    } else {
      mutated.push(nq.replace(/(_:([^\s]+))/g, '<urn:bnid:$2>'));
    }
  }
  return mutated;
}









