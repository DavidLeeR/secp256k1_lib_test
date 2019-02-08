# secp256k1_lib_test
testing using the bitcoin/ethereum secp256k1 generating/signing library

## This branch is attempting to use the secp256k1_ecdsa_sign() function as exemplified in https://github.com/ethereum/aleth/blob/master/libdevcrypto/Common.cpp (ie. the Ethereum C++ implementation source code) at line 235
### *Note: the exemplified function is not the exact same as secp256k1_ecdsa_sign(), and this may lead to problems. I am yet unable to find the header file for the exemplified function (secp256k1_ecdsa_sign_recoverable())


## Dependencies:
- Boost C++ library must be installed prior to build

## Build:
- run command **make** in the root directory

## Notes:
- this build seems to need the h256 data type (hence all the extra header files in the include dir)

