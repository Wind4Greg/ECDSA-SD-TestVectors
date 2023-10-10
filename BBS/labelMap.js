import { base64url } from 'multiformats/bases/base64'

/*
  Shuffling blank node id label map function based on HMAC for potential
  use with BBS to avoid linkability.
*/
export function createShuffledIdLabelMapFunction ({ hmac } = {}) {
  return async ({ canonicalIdMap }) => {
    const te = new TextEncoder()
    const bnodeIdMap = new Map()
    for (const [input, c14nLabel] of canonicalIdMap) {
      const utf8Bytes = te.encode(c14nLabel)
      console.log(`c14nLabel: ${c14nLabel}`)
      const hashed = await hmac.sign(utf8Bytes)
      // multibase prefix of `u` is important to make bnode ID syntax-legal
      // see: https://www.w3.org/TR/n-quads/#BNodes
      bnodeIdMap.set(input, `u${base64url.encode(hashed)}`)
    }
    const hmacIds = [...bnodeIdMap.values()].sort()
    const bnodeKeys = [...bnodeIdMap.keys()]
    bnodeKeys.forEach(bkey => {
      bnodeIdMap.set(bkey, 'b' + hmacIds.indexOf(bnodeIdMap.get(bkey)))
    })
    // console.log(hmacIds)
    // console.log('bnodeIdMap:')
    // console.log(bnodeIdMap)
    return bnodeIdMap
  }
}
