/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <assert.h>
#include <time.h>

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"
#include "helper.h"

//helper function for testSignEcdsa()
void random_scalar_order_test_new(secp256k1_scalar *num) {
   do {
       unsigned char b32[32];
       int overflow = 0;
       secp256k1_rand256(b32);
       secp256k1_scalar_set_b32(num, b32, &overflow);
       if (overflow || secp256k1_scalar_is_zero(num)) {
           continue;
       }
       break;
   } while(1);
}

//helper function for calculating size of string
size_t strlen(const char *str)
{
    const char *s;
    for (s = str; *s; ++s);
    return(s - str);
}

//helper function to get hex from string char
static unsigned char gethex(const char *s, char **endptr) {
 assert(s);
 assert(*s);
 return strtoul(s, endptr, 16);
}

//helper function to convert from string to unsigned char array of hex
unsigned char *convert(const char *s, int *length) 
{
    unsigned char *answer = malloc((strlen(s) + 1) / 3);
    unsigned char *p;
    for (p = answer; *s; p++)
    {
        *p = gethex(s, (char **)&s);
        s++;
    }
    *length = p - answer;
    return answer;
}

//insert spaces between each hex number in string
char* insertSpaces(const char *s)
{
    char *returnString = malloc(sizeof(char)*97);
    int paramStringIndex = 0;
    
    //iterate over new array copying the passed array and adding
    //a space after every 2 chars
    for (int i = 0; i < 97; i++)
    {
        if (i == 96)
        {
            returnString[i] = '\0';
        }
        else if (i%3 == 0)
        {
            returnString[i] = ' ';
        }
        else
        {
            returnString[i] = s[paramStringIndex];
            paramStringIndex++;
        }
    }
    return returnString;
}

//prints the secret key, public key, digest, and signature
void printValues(unsigned char* secKey, unsigned char* pubKey, unsigned char* digest, unsigned char* signature)
{
    //print the private key
    printf("Private key: \n");
    for (int j = 0; j < 32; j++)
    {
        printf("%02x", secKey[j]);
    }
    printf("\n\n");

    //print the corresponding public key
    printf("Public key: \n");
    for (int m = 0; m < 64; m++)
    {
        printf("%02x", pubKey[m]);
    }
    printf("\n\n");

    //print the message hash
    printf("Message hash: \n");
    for (int k = 0; k < 32; k++)
    {
        //make sure all outputted hexes have 2 digits
        printf("%02x", digest[k]);
    }
    printf("\n\n");

    //print signature in hex
    printf("Signature: \n");
    for (int i = 0; i < 64; i++)
    {
        printf("%02x", signature[i]);
    }
    printf("\n\n");
}