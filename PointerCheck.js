/*
    Check to see if our example mandatory pointers work the way we thought they
    should

*/

import { readFile, writeFile } from 'fs/promises'
import jsPointer from 'json-pointer'

// Read input document from a file or just specify it right here.
const document = JSON.parse(
  await readFile(
    new URL('./input/windDoc.json', import.meta.url)
  )
)

const pointers = JSON.parse(
  await readFile(
    new URL('./input/windMandatory.json', import.meta.url)
  )
)

console.log(document)
console.log(pointers)
pointers.forEach(function (pointer) {
  const has = jsPointer.has(document, pointer)
  console.log(`${has} Document containers ${pointer}`)
})
pointers.forEach(function (pointer) {
  const value = jsPointer.get(document, pointer)
  console.log(`Pointer ${pointer} has value:`)
  console.log(value)
})
