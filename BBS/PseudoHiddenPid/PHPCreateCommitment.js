/*
    Walking through the steps for producing a commitment with proof
    for a *holderSecret* for use in either Anonymous Holder Binding or Hidden Pid
    Pseudonym features.
    **CAUTION**: The two different cases use different BBS API_IDs!!!
*/
import { mkdir, readFile, writeFile } from 'fs/promises'
import { API_ID_PSEUDONYM_BBS_SHA, hexToBytes, bytesToHex, numberToHex } from '../lib/BBS.js'
import {commit} from '../lib/BlindBBS.js'

// Create output directory for the test vectors
const baseDir = '../output/bbs/PseudoHiddenPid/'
await mkdir(baseDir, { recursive: true })
const holderSecret = JSON.parse(
  await readFile(new URL('../../input/holderSecret.json', import.meta.url)))
console.log(holderSecret.pidHex)
const pidMaterial = hexToBytes(holderSecret.pidHex)
const [commitWithProofOcts, secretProverBlind] = await commit([pidMaterial], API_ID_PSEUDONYM_BBS_SHA);
const commitInfo = {
  secretProverBlind: numberToHex(secretProverBlind, 32),
  commitmentWithProof: bytesToHex(commitWithProofOcts)
}
await writeFile(baseDir + 'commitmentInfo.json', JSON.stringify(commitInfo, null, 2))
