#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"


void random_scalar_order_test_new(secp256k1_scalar *num) {
   do {
       unsigned char b32[32];
       int overflow = 0;
       secp256k1_rand256_test(b32);
       secp256k1_scalar_set_b32(num, b32, &overflow);
       if (overflow || secp256k1_scalar_is_zero(num)) {
           continue;
       }
       break;
   } while(1);
}

int main() 
{
    srand(time(0));
    /*a general template for this function can be found in 
    go-ethereum-master\crypto\secp256k1\libsecp256k1\src\modules\recovery\tests_impl.h
    line 150*/

    //setup params needed for signing function
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_signature mySig;
    secp256k1_scalar myMessageHash, myPrivateKey;
    secp256k1_pubkey myPublicKey;
    unsigned char myMessageHash32[32], myPrivateKey32[32];
    unsigned char sig[74];

    //generate random message hash and private key?
    random_scalar_order_test_new(&myMessageHash);
    random_scalar_order_test_new(&myPrivateKey);
    
    //convert message hash to unsigned char 32 bytes?
    secp256k1_scalar_get_b32(myMessageHash32, &myMessageHash);
    secp256k1_scalar_get_b32(myPrivateKey32, &myPrivateKey);

    //print the message hash
    printf("Message hash: \n");
    for (int k = 0; k < 32; k++)
    {
        printf("%x", myMessageHash32[k]);
    }
    printf("\n\n");

    //print the test private key
    printf("Private key: \n");
    for (int j = 0; j < 32; j++)
    {
        printf("%x", myPrivateKey32[j]);
    }
    printf("\n\n");

    //verify the private key
    if(1 == secp256k1_ec_seckey_verify(myContext, myPrivateKey32))
    {
        printf("Private key verified\n\n");
    }
    else
    {
        printf("Private key failed verification\n\n");
    }

    //construct the corresponding public key
    if(1 == secp256k1_ec_pubkey_create(myContext, &myPublicKey, myPrivateKey32))
    {
        printf("Public key created\n\n");
    }
    else
    {
        printf("Public key could not be created\n\n");
    }

    //print the corresponding public key
    printf("Public key: \n");
    for (int m = 0; m < 64; m++)
    {
        printf("%x", mySig.data[m]);
    }
    printf("\n\n");
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, myMessageHash32, myPrivateKey32, NULL, NULL);

    //print signature in hex
    printf("Signature: \n");
    for (int i = 0; i < 64; i++)
    {
        printf("%x", mySig.data[i]);
    }
    printf("\n");

    return 0;
}

/*
LOG

1/11/16 - does not compile, needs declarations/implementations for "secp256k1_scaler" and "secp256k1_scalar_get_b32"

        - compilation works after including more headers and typedef for uint128 in scalar_4_64, need to check output somehow

1/12/16 - compiles and outputs signature

        - need to verify signature and customize inputs to signature function

        - debug statements added

*/