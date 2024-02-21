/*
    Different CBOR libraries produce different outputs due to tagging Uint8Arrays.
    Seeing if we can turn it off and if outputs are the same.
*/
import { readFile } from 'fs/promises'
import cbor from 'cbor'
import { encode } from 'cborg'
import { Encoder } from 'cbor-x';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'

const data = JSON.parse(
  await readFile(new URL('./input/cborCheckInput.json', import.meta.url)))
const baseSignature = hexToBytes(data.baseSignature)
const hmacKey = hexToBytes(data.hmacKeyString)
const signatures = data.signatures.map(sigHex => hexToBytes(sigHex))
const mandatoryPointers = data.mandatoryPointers
const components = [baseSignature, hmacKey, signatures, mandatoryPointers]

const cborThing = await cbor.encodeAsync(components)
console.log('CBOR library encoding hex:')
const cborThingHex = bytesToHex(cborThing)
console.log(cborThingHex)

const cborgThing = await encode(components)
console.log('CBORG library encoding hex:')
const cborgThingHex = bytesToHex(cborgThing)
console.log(cborgThingHex)

const cborXEncoder = new Encoder({ tagUint8Array: false })
const cborxThing = cborXEncoder.encode(components)
console.log('CBOR-X library encoding hex:')
const cborxThingHex = bytesToHex(cborxThing)
console.log(cborxThingHex)

console.log(`cborx == cborg? ${cborgThingHex === cborxThingHex}`)
console.log(`cbor == cborg? ${cborThingHex === cborxThingHex}`)
