/*
    Walking through the steps for producing a commitment with proof
    for a *holderSecret* for use in either Anonymous Holder Binding or Hidden Pid
    Pseudonym features.
*/
import { mkdir, readFile, writeFile } from 'fs/promises'
import { API_ID_BLIND_BBS_SHA,  hexToBytes, bytesToHex, numberToHex } from '../lib/BBS.js'
import {commit} from '../lib/BlindBBS.js'

// Create output directory for the test vectors
const baseDir = '../output/bbs/HolderBinding/'
await mkdir(baseDir, { recursive: true })
const holderSecret = JSON.parse(
  await readFile(new URL('../../input/holderSecret.json', import.meta.url)))
console.log(holderSecret.pidHex)
const pidMaterial = hexToBytes(holderSecret.holderSecretHex)
const [commitWithProofOcts, secretProverBlind] = await commit([pidMaterial], API_ID_BLIND_BBS_SHA);
const commitInfo = {
  secretProverBlind: numberToHex(secretProverBlind, 32),
  commitmentWithProof: bytesToHex(commitWithProofOcts)
}
await writeFile(baseDir + 'commitmentInfo.json', JSON.stringify(commitInfo, null, 2))
