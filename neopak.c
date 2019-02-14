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
struct Tuple2 testSignEcdsa()
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

    //testing if verify sig will fail if private key manually changed before public key creation
    //EXPECTED RESULT: sig verify should not fail
    //RESULT: verify does not fail
    //myPrivateKey32[0] = 0;
    //myPrivateKey32[5] = 0;

    //verify the private key
    if(1 == secp256k1_ec_seckey_verify(myContext, myPrivateKey32))
    {
        printf("\nPrivate key verified\n\n");
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
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, myMessageHash32, myPrivateKey32, NULL, NULL);

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

    struct Tuple2 returnVals = { myPublicKey, mySig, myPrivateKey32, myMessageHash32};
    return returnVals;
}

//creates an ECDSA signature using the passed in message hash and private key
struct Tuple signEcdsaKeyAndHashArgs(unsigned char* myPrivateKey32, unsigned char* myMessageHash32)
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
    ////this will end up holding the signature
    unsigned char sig[74];

    //testing if verify sig will fail if private key manually changed before public key creation
    //EXPECTED RESULT: sig verify should not fail
    //RESULT: verify does not fail
    //myPrivateKey32[0] = 0;
    //myPrivateKey32[5] = 0;

    //verify the private key
    if(1 == secp256k1_ec_seckey_verify(myContext, myPrivateKey32))
    {
        printf("\nPrivate key verified\n\n");
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
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, myMessageHash32, myPrivateKey32, NULL, NULL);

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

    struct Tuple returnVals = { myPublicKey, mySig};
    return returnVals;
}

int main(int argc, char **argv) 
{
    unsigned char* ucDigest;
    unsigned char* ucSecKey;
    unsigned char* ucPubKey;
    unsigned char* ucSignature;
    struct Tuple pubKeyAndSig;
    struct Tuple2 allSigInfo;

    srand(time(NULL));


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
            allSigInfo = testSignEcdsa();
            ucDigest = allSigInfo.digest;
            ucSecKey = allSigInfo.secKey;
            ucPubKey = allSigInfo.pubKey.data;
            ucSignature = allSigInfo.signature.data;

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
        ucSecKey = convert(secKey, keyLengthPtr);
        ucDigest = convert(digest, digestLengthPtr);
        pubKeyAndSig = signEcdsaKeyAndHashArgs(ucSecKey, ucDigest);
        ucPubKey = pubKeyAndSig.pubKey.data;
        ucSignature = pubKeyAndSig.signature.data;
    }
    //else, too many args passed
    else
    {
        printf("\nError: incorrect usage, run program with no args for usage info\n\n");
    }
    
    //print values
    printValues(ucSecKey, ucPubKey, ucDigest, ucSignature);
    return 0;
}

/*
LOG

2/11/19 - does not compile, needs declarations/implementations for "secp256k1_scaler" and "secp256k1_scalar_get_b32"
        - compilation works after including more headers and typedef for uint128 in scalar_4_64, need to check output somehow

2/12/19 - compiles and outputs signature
        - need to verify signature and customize inputs to signature function
        - debug statements added
        - verify signature implemented
        - priv/pub key creation, signing, and verification seemingly working

2/13/19 - printing of hex's fixed
        - testSign function separated from main()
        - usage info added
        - 3 options added to command line (usage, test sign, production sign)
            -prod sign not yet implemented
        - prod sign half implemented (custom priv key working)

2/14/19 - separated helper functions from neopak.c
        - private key can now be passed with no spaces
        - digest can now be passed with no spaces
        - input validation for length of digest and priv key added
        - placed printing values into separate function
*/

//TEST WITH THIS:
//private key: 6f910beb039b93eba3bf95eb9ab2610855f18a7512463c78bc9ebf774535e89f
//digest: 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a