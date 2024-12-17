/*
    Check to see if our example mandatory pointers work the way we thought they
    should and generate a test vector.

*/

import { mkdir, readFile, writeFile } from 'fs/promises'
import jsPointer from 'json-pointer'
// Set input file and output directory here
// const dirsAndFiles = {
//   outputDir: './output/ecdsa-sd-2023/',
//   inputFile: './input/windDoc.json',
//   mandatoryFile: './input/windMandatory.json'
// }
// const dirsAndFiles = {
//   outputDir: './output/ecdsa-sd-2023/employ/',
//   inputFile: './input/employmentAuth.json',
//   mandatoryFile: './input/employMandatory.json'
// }
const dirsAndFiles = {
  outputDir: './output/ecdsa-sd-2023/prc/',
  inputFile: './input/prCredUnsigned.json',
  mandatoryFile: './input/prCredMandatory.json'
}
// Create output directory for the test vectors
const baseDir = dirsAndFiles.outputDir
const status = await mkdir(baseDir, { recursive: true })

// Read input document from a file or just specify it right here.
const document = JSON.parse(
  await readFile(
    new URL(dirsAndFiles.inputFile, import.meta.url)
  )
)

const pointers = JSON.parse(
  await readFile(
    new URL(dirsAndFiles.mandatoryFile, import.meta.url)
  )
)

console.log(document)
console.log(pointers)
pointers.forEach(function (pointer) {
  const has = jsPointer.has(document, pointer)
  console.log(`${has} Document containers ${pointer}`)
})
const pointerValues = []
pointers.forEach(function (pointer) {
  const value = jsPointer.get(document, pointer)
  console.log(`Pointer ${pointer} has value:`)
  console.log(value)
  const entry = { pointer, value }
  pointerValues.push(entry)
})
await writeFile(baseDir + 'addPointerValues.json', JSON.stringify(pointerValues, null, 2))
