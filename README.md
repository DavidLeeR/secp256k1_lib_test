# secp256k1_lib_test
testing using the bitcoin/ethereum secp256k1 signing library

## This branch is attempting to use the secp256k1_ecdsa_sign() function as exemplified in https://github.com/ethereum/go-ethereum/blob/master/crypto/secp256k1/libsecp256k1/src/tests_exhaustive.c (ie. the Ethereum GO implementation source code, in the libsecp256k1 library folder) at line 235

## Dependencies:
- GMP C library must be installed prior to build
- install using Homebrew: **brew install gmp**

## Build:
- run command **make** in the root directory


