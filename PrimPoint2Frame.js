/*
    Checking SD-Primitive: pointersToFrame
    function pointersToFrame({document, pointers, includeTypes = true} = {})

    Also try using it:
     async function frame(document, frame, options)
*/

import { readFile, writeFile } from 'fs/promises';
import { pointersToFrame, frame} from '@digitalbazaar/di-sd-primitives';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';


jsonld.documentLoader = localLoader; // Local loader for JSON-LD

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL('./input/windDoc.json', import.meta.url)
    )
  );

const pointers1 = ["/sailNumber", "/sails/1", "/boards/0/year"];

let frame1 = await pointersToFrame({document, pointers: pointers1, includeTypes: true});
console.log(frame1);
let selected1 = await frame(document, frame1);
console.log(selected1);

// Try selecting two sails
const pointers2 = ["/sailNumber", "/sails/1", "/boards/0/year", "/sails/2"];
let frame2 = await pointersToFrame({document, pointers: pointers2, includeTypes: true});
console.log(frame2);
let selected2 = await frame(document, frame2);
console.log(selected2);

/*

*/
