/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include <assert.h>

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
 //if character is whitespace, move on to the next char
 //while (isspace(*s)) s++;
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