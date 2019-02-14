/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"
#include "helper.h"

//displays usage info
void usage()
{
    printf("\nNeoPak\nCopywrite NeoWare 2019\n");
    printf("Created by David Lee Ramirez 2/12/2019\n\n");
    printf("Usage:\n");
    printf("./neopak                                  Show usage info\n");
    printf("./neopak test                             Sign with test priv key and message hash\n");
    printf("./neopak <privKey> <messageHash>          Sign with provided priv key and message hash\n");
}

//creates a test ECDSA signature using a test message hash and a test private key
void testSignEcdsa()
{
    /*a general template for this function can be found in 
    go-ethereum-master\crypto\secp256k1\libsecp256k1\src\modules\recovery\tests_impl.h
    line 150*/

    //setup params needed for signing function
    ////set to both sign and verify
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY); 
    secp256k1_ecdsa_signature mySig;
    //holds four 64 bit uints (0 to 18,446,744,073,709,551,615) in an array
    secp256k1_scalar myMessageHash, myPrivateKey;
    secp256k1_pubkey myPublicKey;
    unsigned char myMessageHash32[32], myPrivateKey32[32];
    ////this will end up holding the signature
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
        //make sure all outputted hexes have 2 digits
        printf("%02x", myMessageHash32[k]);
    }
    printf("\n\n");


    //testing if verify sig will fail if private key manually changed before public key creation
    //EXPECTED RESULT: sig verify should not fail
    //RESULT: verify does not fail
    //myPrivateKey32[0] = 0;
    //myPrivateKey32[5] = 0;

    //print the test private key
    printf("Private key: \n");
    for (int j = 0; j < 32; j++)
    {
        printf("%02x", myPrivateKey32[j]);
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
        printf("%02x", myPublicKey.data[m]);
    }
    printf("\n\n");
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, myMessageHash32, myPrivateKey32, NULL, NULL);

    //print signature in hex
    printf("Signature: \n");
    for (int i = 0; i < 64; i++)
    {
        printf("%02x", mySig.data[i]);
    }
    printf("\n\n");

    //test to see if sig verify will fail if signature manually changed
    //EXPECTED RESULT: sig verify should fail
    //RESULT: sig verify fails
    //mySig.data[0] = 0;
    //mySig.data[5] = 0;

    //test to see if sig verify will fail if public key manually changed after signing
    //EXPECTED RESULT: sig verify should fail
    //RESULT: sig verify fails
    //myPublicKey.data[0] = 0;
    //myPublicKey.data[5] = 0;

    //verify signature
    if (1 == secp256k1_ecdsa_verify(myContext, &mySig, myMessageHash32, &myPublicKey))
    {
        printf("Signature verified\n");
    }
    else
    {
        printf("Signature could not be verified\n");
    }
}

//creates an ECDSA signature using the passed in message hash and private key
secp256k1_ecdsa_signature signEcdsaKeyAndHashArgs(unsigned char* myPrivateKey32)
{
    /*a general template for this function can be found in 
    go-ethereum-master\crypto\secp256k1\libsecp256k1\src\modules\recovery\tests_impl.h
    line 150*/

    //setup params needed for signing function
    ////set to both sign and verify
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY); 
    secp256k1_ecdsa_signature mySig;
    //holds four 64 bit uints (0 to 18,446,744,073,709,551,615) in an array
    secp256k1_scalar myMessageHash, myPrivateKey;
    secp256k1_pubkey myPublicKey;
    unsigned char myMessageHash32[32]; //, myPrivateKey32[32];
    ////this will end up holding the signature
    unsigned char sig[74];

    //generate random message hash and private key?
    random_scalar_order_test_new(&myMessageHash);
    //random_scalar_order_test_new(&myPrivateKey);
    
    //convert message hash to unsigned char 32 bytes?
    secp256k1_scalar_get_b32(myMessageHash32, &myMessageHash);
    //secp256k1_scalar_get_b32(myPrivateKey32, &myPrivateKey);

    //print the message hash
    printf("Message hash: \n");
    for (int k = 0; k < 32; k++)
    {
        //make sure all outputted hexes have 2 digits
        printf("%02x", myMessageHash32[k]);
    }
    printf("\n\n");


    //testing if verify sig will fail if private key manually changed before public key creation
    //EXPECTED RESULT: sig verify should not fail
    //RESULT: verify does not fail
    //myPrivateKey32[0] = 0;
    //myPrivateKey32[5] = 0;

    //print the test private key
    printf("Private key: \n");
    for (int j = 0; j < 32; j++)
    {
        printf("%02x", myPrivateKey32[j]);
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
        printf("%02x", myPublicKey.data[m]);
    }
    printf("\n\n");
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, myMessageHash32, myPrivateKey32, NULL, NULL);

    //print signature in hex
    printf("Signature: \n");
    for (int i = 0; i < 64; i++)
    {
        printf("%02x", mySig.data[i]);
    }
    printf("\n\n");

    //test to see if sig verify will fail if signature manually changed
    //EXPECTED RESULT: sig verify should fail
    //RESULT: sig verify fails
    //mySig.data[0] = 0;
    //mySig.data[5] = 0;

    //test to see if sig verify will fail if public key manually changed after signing
    //EXPECTED RESULT: sig verify should fail
    //RESULT: sig verify fails
    //myPublicKey.data[0] = 0;
    //myPublicKey.data[5] = 0;

    //verify signature
    if (1 == secp256k1_ecdsa_verify(myContext, &mySig, myMessageHash32, &myPublicKey))
    {
        printf("Signature verified\n");
    }
    else
    {
        printf("Signature could not be verified\n");
    }

    return mySig;
}

int main(int argc, char **argv) 
{
    unsigned char* uDigest;
    unsigned char* uSecKey;
    secp256k1_ecdsa_signature signature;
    //digest = malloc(64 *sizeof)
    //if no args passed, display usage info
    if (argc == 1)
    {
        usage();
        return 0;
    }
    //if only "test" is passed as arg, start test sign
    else if (argc == 2)
    {
        if(strcmp(argv[1],"test") == 0)
        {
            printf("\nStarting signing test with test pub/priv keys and test message hash\n\n");
            testSignEcdsa();
        }
        else
        {
            printf("\nError: incorrect usage, run program with no args for usage info\n\n");
        }
    }
    //if private key and message hash are passed as args, start
    //production sign
    else if (argc == 3)
    {
        //make sure passed private key and digest are exactly 64 chars long
        if (strlen(argv[1]) != 64 || strlen(argv[2]) != 64)
        {
            printf("\nError: incorrect usage, private key and message hash must be exaclty 64 chars long\n\n");
            return 0;
        }
      
        //add space between each hex number in private key and digest 
        const char* secKey = insertSpaces(argv[1]);
        const char* digest = insertSpaces(argv[2]);
        int lengthKey = strlen(secKey);
        int lengthDigest = strlen(digest);
        int *keyLengthPtr = &lengthKey;
        int *digestLengthPtr = &lengthKey;
        //convert args (string) into array of hex numbers stored
        //as unsigned chars
        uSecKey = convert(secKey, keyLengthPtr);
        uDigest = convert(digest, digestLengthPtr);
        signature = signEcdsaKeyAndHashArgs(uSecKey);
    }
    //else, too many args passed
    else
    {
        printf("\nError: incorrect usage, run program with no args for usage info\n\n");
    }
    
    return 0;
}

/*
LOG

1/11/19 - does not compile, needs declarations/implementations for "secp256k1_scaler" and "secp256k1_scalar_get_b32"
        - compilation works after including more headers and typedef for uint128 in scalar_4_64, need to check output somehow

1/12/19 - compiles and outputs signature
        - need to verify signature and customize inputs to signature function
        - debug statements added
        - verify signature implemented
        - priv/pub key creation, signing, and verification seemingly working

1/13/19 - printing of hex's fixed
        - testSign function separated from main()
        - usage info added
        - 3 options added to command line (usage, test sign, production sign)
            -prod sign not yet implemented
        - prod sign half implemented (custom priv key working)

1/14/19 - separated helper functions from neopak.c
        - private key can now be passed with no spaces

*/