/************************************
 * Project: NeoPak
 * Author: David Lee Ramirez
 * Date: 2/12/19
 * Copywrite NeoWare 2019
 * *********************************/

#include "include/secp256k1.h"
#include "include/scalar.h"
#include "include/scalar_4x64_impl.h"
#include "include/scalar_4x64.h"
#include "include/testrand_impl.h"

//helper function for testSignEcdsa()
void random_scalar_order_test_new(secp256k1_scalar *num);

//helper function for calculating size of string
size_t strlen(const char *str);

//helper function to get hex from string char
static unsigned char gethex(const char *s, char **endptr);

//helper function to convert from string to unsigned char array of hex
unsigned char *convert(const char *s, int *length);



