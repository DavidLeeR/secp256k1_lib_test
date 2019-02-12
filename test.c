#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"


int main() 
{
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_signature mySig;

    /*according to code in tests_exhaustive.c line 258 (within go-ethereum-master) project, we should
    be able to use this format for the key and message*/
    secp256k1_scalar myMessageHash, myPrivateKey;
    unsigned char myMessageHash32[32], myPrivateKey32[32];

    secp256k1_scalar_get_b32(myMessageHash32, &myMessageHash);
    secp256k1_scalar_get_b32(myPrivateKey32, &myPrivateKey);


    const unsigned char *myMessageHashPtr = &myMessageHash;
    const unsigned char *myPrivateKeyPtr = &myPrivateKey;

    secp256k1_ecdsa_sign(myContext, &mySig, myMessageHash32, myPrivateKey32, NULL, NULL);

    return 0;
}

/*
LOG

1/11/16 - does not compile, needs declarations/implementations for "secp256k1_scaler" and "secp256k1_scalar_get_b32"

        - compilation works after including more headers and typedef for uint128 in scalar_4_64, need to check output somehow

*/