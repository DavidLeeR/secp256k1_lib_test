#include <stdio.h>
#include "include/secp256k1.h"

int main() 
{
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_signature mySig;

    /*the following 2 variables not currently working correctly, they need to be in either uint256 from (Bitcoin) or h256 form (Ethereum)
    This requires that we include more source code from Ethereum C++ repo*/

    /*according to code in tests_exhaustive.c (within go-ethereum-master) project, we should
    be able to use this format for the key and message*/
    secp256k1_scalar msg;
    unsigned char myMessageHash[32], myPrivateKey[32];

    secp256k1_scalar_get_b32(msg32, &msg);


    const unsigned char *myMessageHashPtr = &myMessageHash;
    const unsigned char *myPrivateKeyPtr = &myPrivateKey;

    secp256k1_ecdsa_sign(myContext, &mySig, myMessageHashPtr, myPrivateKeyPtr, NULL, NULL);

    return 0;
}