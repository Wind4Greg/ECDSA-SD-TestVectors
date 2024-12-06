/*  Generate some random BLS12-381 G1 appropriate scalars in hex.
    Use them where you need random scalars for test vectors!
*/
import { calculate_random_scalars } from "./lib/BBS.js";

const count = 5;
const scalars = calculate_random_scalars(count);
const hexScalars = scalars.map(scalar => scalar.toString(16));
console.log('Random BLS12-381 G1 scalar values:');
console.log(JSON.stringify(hexScalars, null, 2));