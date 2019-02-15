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
    printf("\n *Note: <privKey> and <messageHash> must be supplied \n        as a string of hex numbers with length 64\n\n");
}

//creates a test ECDSA signature using a test message hash and a test private key
int testSignEcdsa(unsigned char* secKey, unsigned char* pubKeyComp, unsigned char* pubKeyUncomp, unsigned char* digest, unsigned char* signature)
{
    /*a general template for this function can be found in 
    go-ethereum-master\crypto\secp256k1\libsecp256k1\src\modules\recovery\tests_impl.h
    line 150*/

    //setup params needed for signing function
    //set to both sign and verify
    secp256k1_context *myContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN| SECP256K1_CONTEXT_VERIFY); 
    secp256k1_ecdsa_signature mySig;
    //holds four 64 bit uints (0 to 18,446,744,073,709,551,615) in an array
    secp256k1_scalar myMessageHash, myPrivateKey;
    secp256k1_pubkey myPublicKey;
    size_t pubKeyCompLen;
    size_t pubKeyUncompLen;

    //generate random message hash and private key?
    random_scalar_order_test_new(&myMessageHash);
    random_scalar_order_test_new(&myPrivateKey);
    
    //convert message hash to unsigned char 32 bytes?
    secp256k1_scalar_get_b32(digest, &myMessageHash);
    secp256k1_scalar_get_b32(secKey, &myPrivateKey);

    //verify the private key
    if(1 == secp256k1_ec_seckey_verify(myContext, secKey))
    {
        printf("Private key verified\n\n");
    }
    else
    {
        printf("Private key failed verification\n\n");
        exit(1);
    }

    //construct the corresponding public key
    if(1 == secp256k1_ec_pubkey_create(myContext, &myPublicKey, secKey))
    {
        printf("Public key created\n\n");
    }
    else
    {
        printf("Public key could not be created\n\n");
        exit(1);
    }

    //get seralized public key (compressed)
    pubKeyCompLen = 33;
    secp256k1_ec_pubkey_serialize(myContext, pubKeyComp, &pubKeyCompLen, &myPublicKey, SECP256K1_EC_COMPRESSED);
    secp256k1_pubkey pubkeytest0;
    if (1 == secp256k1_ec_pubkey_parse(myContext, &pubkeytest0, pubKeyComp, pubKeyCompLen)) 
    {
        printf("Compressed public key able to be parsed\n\n");
    }
    else
    {
        printf("Error parsing compressed public key\n\n");
        exit(1);
    }

    //get seralized public key (uncompressed)
    pubKeyUncompLen = 65;
    secp256k1_ec_pubkey_serialize(myContext, pubKeyUncomp, &pubKeyUncompLen, &myPublicKey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_pubkey pubkeytest1;
    if (1 == secp256k1_ec_pubkey_parse(myContext, &pubkeytest1, pubKeyUncomp, pubKeyUncompLen)) 
    {
        printf("Uncompressed public key able to be parsed\n\n");
    }
    else
    {
        printf("Error parsing uncompressed public key\n\n");
        exit(1);
    }
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, digest, secKey, NULL, NULL);

    //verify signature
    if (1 == secp256k1_ecdsa_verify(myContext, &mySig, digest, &myPublicKey))
    {
        printf("Signature verified\n\n");
    }
    else
    {
        printf("Signature could not be verified\n\n");
        exit(1);
    }

    //copy data of signature into hex array
    for (int x = 0; x < 74; x++)
    {
        signature[x] = mySig.data[x];
    }

    return 1;
}

//creates an ECDSA signature using the passed in message hash and private key
struct Tuple signEcdsaKeyAndHashArgs(unsigned char* secKey, unsigned char* digest)
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

    //verify the private key
    if(1 == secp256k1_ec_seckey_verify(myContext, secKey))
    {
        printf("\nPrivate key verified\n\n");
    }
    else
    {
        printf("Private key failed verification\n\n");
        exit(1);
    }

    //construct the corresponding public key
    if(1 == secp256k1_ec_pubkey_create(myContext, &myPublicKey, secKey))
    {
        printf("Public key created\n\n");
    }
    else
    {
        printf("Public key could not be created\n\n");
        exit(1);
    }
    
    //sign message hash with private key
    secp256k1_ecdsa_sign(myContext, &mySig, digest, secKey, NULL, NULL);

    //verify signature
    if (1 == secp256k1_ecdsa_verify(myContext, &mySig, digest, &myPublicKey))
    {
        printf("Signature verified\n\n");
    }
    else
    {
        printf("Signature could not be verified\n");
        exit(1);
    }

    struct Tuple returnVals = { myPublicKey, mySig};
    return returnVals;
}

int main(int argc, char **argv) 
{
    unsigned char* serializedDigest;
    unsigned char* serializedSecKey;
    unsigned char* serializedPubKeyCompressed;
    unsigned char* serializedPubKeyUncompressed;
    unsigned char* serializedSignature;
    serializedDigest = malloc(sizeof(unsigned char)*32);
    serializedSecKey = malloc(sizeof(unsigned char)*32);
    serializedPubKeyCompressed = malloc(sizeof(unsigned char)*33);
    serializedPubKeyUncompressed = malloc(sizeof(unsigned char)*65);
    serializedSignature = malloc(sizeof(unsigned char)*74);
    struct Tuple pubKeyAndSig;

    srand(time(NULL));


    //if no args passed, display usage info
    if (argc == 1)
    {
        usage();
        exit(0);
    }
    //if only "test" is passed as arg, start test sign
    else if (argc == 2)
    {
        if(strcmp(argv[1],"test") == 0)
        {
            printf("\nStarting signing test with test pub/priv keys and test message hash\n\n");
            testSignEcdsa(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, serializedDigest, serializedSignature);

        }
        else
        {
            printf("\nError: incorrect usage, run program with no args for usage info\n\n");
            exit(1);
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
            exit(0);
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
        serializedSecKey = convert(secKey, keyLengthPtr);
        serializedDigest = convert(digest, digestLengthPtr);
        pubKeyAndSig = signEcdsaKeyAndHashArgs(serializedSecKey, serializedDigest);
        //serializedPubKey = pubKeyAndSig.pubKey.data;
        serializedSignature = pubKeyAndSig.signature.data;
    }
    //else, too many args passed
    else
    {
        printf("\nError: incorrect usage, run program with no args for usage info\n\n");
        exit(1);
    }
    
    //print values
    printValues(serializedSecKey, serializedPubKeyCompressed, serializedPubKeyUncompressed, serializedDigest, serializedSignature);
    return 0;
}

//TEST WITH THIS:
//private key: 6f910beb039b93eba3bf95eb9ab2610855f18a7512463c78bc9ebf774535e89f
//digest: 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a