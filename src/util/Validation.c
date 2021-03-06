#include "sha.h"

#include "util/Validation.h"
#include "util/PrimalityTest.h"


static const int MIGHT_BE_PRIME = 1;

CryptidValidationResult validation_isProbablePrime(const mpz_t p)
{
    return millerrabin_mpz(p, 50) >= MIGHT_BE_PRIME ? CRYPTID_VALIDATION_SUCCESS : CRYPTID_VALIDATION_FAILURE;
}

CryptidValidationResult validation_isAffinePointValid(const AffinePoint affinePoint, const mpz_t order)
{
    if(mpz_cmp_si(affinePoint.x, -1) > 0 && mpz_cmp(affinePoint.x, order) < 0
        && mpz_cmp_si(affinePoint.y, -1) > 0 && mpz_cmp(affinePoint.y, order) < 0)
    {
        return CRYPTID_VALIDATION_SUCCESS;
    }

    return CRYPTID_VALIDATION_FAILURE;
}

CryptidValidationResult validation_isTypeOneEllipticCurve(const EllipticCurve ellipticCurve)
{
    if(!mpz_cmp_ui(ellipticCurve.a, 0)
        && !mpz_cmp_ui(ellipticCurve.b, 1)
        && validation_isProbablePrime(ellipticCurve.fieldOrder))
    {
        return CRYPTID_VALIDATION_SUCCESS;
    }

    return CRYPTID_VALIDATION_FAILURE;
}

CryptidValidationResult validation_isPublicParametersValid(const PublicParameters publicParameters)
{
    if(validation_isTypeOneEllipticCurve(publicParameters.ellipticCurve) 
        && validation_isProbablePrime(publicParameters.q)
        && validation_isAffinePointValid(publicParameters.pointP, publicParameters.ellipticCurve.fieldOrder)  
        && validation_isAffinePointValid(publicParameters.pointPpublic, publicParameters.ellipticCurve.fieldOrder))
    {
        return CRYPTID_VALIDATION_SUCCESS;
    }

    return CRYPTID_VALIDATION_FAILURE;
}

CryptidValidationResult validation_isCipherTextTupleValid(const CipherTextTuple cipherTextTuple, const mpz_t order)
{
    if(validation_isAffinePointValid(cipherTextTuple.cipherU, order)
        && cipherTextTuple.cipherV
        && cipherTextTuple.cipherVLength != 0
        && cipherTextTuple.cipherW
        && cipherTextTuple.cipherWLength != 0)
    {
        return CRYPTID_VALIDATION_SUCCESS;
    }

    return CRYPTID_VALIDATION_FAILURE;
}

CryptidValidationResult validation_isSignatureValid(const Signature signature, const mpz_t order)
{
    if(validation_isAffinePointValid(signature.u, order)
        && signature.v != NULL)
    {
        return CRYPTID_VALIDATION_SUCCESS;
    }
    
    return CRYPTID_VALIDATION_FAILURE;
}
