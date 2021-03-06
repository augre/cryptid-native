#include <stdlib.h>
#include <string.h>

#include "identity-based/CipherTextTuple.h"


CipherTextTuple cipherTextTuple_init(const AffinePoint cipherU, const unsigned char *const cipherV, const int cipherVLength,
                                     const unsigned char *const cipherW, const int cipherWLength)
{
    CipherTextTuple cipherTextTuple;
    cipherTextTuple.cipherU = affine_init(cipherU.x, cipherU.y);
    
    cipherTextTuple.cipherV = (unsigned char*)malloc(cipherVLength * sizeof(unsigned char) + 1);
    memcpy(cipherTextTuple.cipherV, cipherV, cipherVLength + 1);
    
    cipherTextTuple.cipherVLength = cipherVLength;
    
    cipherTextTuple.cipherW = (unsigned char*)malloc(cipherWLength * sizeof(unsigned char) + 1);
    memcpy(cipherTextTuple.cipherW, cipherW, cipherWLength + 1);
    
    cipherTextTuple.cipherWLength = cipherWLength;

    return cipherTextTuple;
}

void cipherTextTuple_destroy(CipherTextTuple cipherTextTuple)
{
    affine_destroy(cipherTextTuple.cipherU);
    free(cipherTextTuple.cipherV);
    free(cipherTextTuple.cipherW);
}
