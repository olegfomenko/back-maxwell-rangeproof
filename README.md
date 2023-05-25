# Back-Maxwell range proof for Pedersen Commitments on Go 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Example implementation of [Back-Maxwell Rangeproof](https://blockstream.com/bitcoin17-final41.pdf) on Go 
for creating the Pedersen commitment with corresponding proof that committed value lies in [0..2^n-1] range.   
Use only for educational reasons. 

__DO NOT USE IN PRODUCTION.__ 

## Usage
Explore [main_test.go](./main_test.go) TestPedersenCommitment with example of usage.

Note, that there are wht following values defined in global space to be changed on your choice:

```go
// Curve - the curve we are working on
var Curve = secp256k1.S256()

// Hash function that should return the value in Curve.N field
var Hash func(...[]byte) *big.Int = defaultHash
```