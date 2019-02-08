#include <stdio.h>
#include "secp256k1.h"

int main() 
{
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_signature mySig;

    const unsigned char *myMessageHashPtr = &myMessageHash;
    const unsigned char *myPrivateKeyPtr = &myPrivateKey;


    /*the following 2 variables not currently working, they need to be in either uint256 from (Bitcoin) or h256 form (Ethereum)
    This requires that we include more source code from Ethereum C++ repo*/
    //unsigned char myMessageHash[65] = "357632a869c2a27ecf8b9fdb74bd0f21489e99acd52ef67f1c0e0b2bc7d9bae6";
    //unsigned char myPrivateKey[65] = "402270cdf114bc39debb75ee68ca4ed61e8000bf2a2ce86394f3b8b00878b7cb";

    secp256k1_ecdsa_sign(myContext, &mySig, myMessageHashPtr, myPrivateKeyPtr, NULL, NULL);

    return 0;
}