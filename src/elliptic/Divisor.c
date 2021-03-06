#include "gmp.h"

#include "elliptic/Divisor.h"


// References
//  * [RFC-5091] Xavier Boyen, Luther Martin. 2007. RFC 5091. Identity-Based Cryptography Standard (IBCS) #1: Supersingular Curve Implementations of the BF and BB1 Cryptosystems


Complex divisor_evaluateVertical(const EllipticCurve ec, const AffinePoint a, const ComplexAffinePoint b)
{
    // Implementation of Algorithm 3.4.1 in [RFC-5091].

    // Let \f$r\f$ denote the result of the operation:
    // \f$r = x_B - x_A\f$
    Complex result;

    if(affine_isInfinity(a))
    {
        result = complex_initLong(1, 0);
        return result;
    }

    mpz_t axAddInv;
    mpz_init(axAddInv);
    mpz_neg(axAddInv, a.x);
    mpz_mod(axAddInv, axAddInv, ec.fieldOrder);

    result = complex_modAddScalar(b.x, axAddInv, ec.fieldOrder);

    mpz_clear(axAddInv);

    return result;
}

CryptidStatus divisor_evaluateTangent(Complex* result, const EllipticCurve ec, const AffinePoint a, const ComplexAffinePoint b)
{
    // Implementation of Algorithm 3.4.2 in [RFC-5091].

    // Argument check
    if(complexAffine_isInfinity(b))
    {
        return CRYPTID_DIVISOR_OF_TANGENT_INFINITY_ERROR;
    }

    // Special cases
    if(affine_isInfinity(a))
    {
        *result = complex_initLong(1, 0);
        return CRYPTID_SUCCESS;
    }

    if(!mpz_cmp_ui(a.y, 0))
    {
        *result = divisor_evaluateVertical(ec, a, b);
        return CRYPTID_SUCCESS;
    }

    Complex axB, byB, resultPart;
    mpz_t threeAddInv, minusThree, xasquared, aprime, bprime, bAddInv, bAddInvyA, axA, axAaddInv, c;
    mpz_inits(threeAddInv, minusThree, xasquared, aprime, bprime, bAddInv, bAddInvyA, axA, axAaddInv, c, NULL);

    // Line computation
    // \f$a^{\prime} = -3 \cdot x_A^2\f$
    mpz_set_si(minusThree, -3);
    mpz_mod(threeAddInv, minusThree, ec.fieldOrder);
    mpz_powm_ui(xasquared, a.x, 2, ec.fieldOrder);
    mpz_mul(aprime, xasquared, threeAddInv);
    mpz_mod(aprime, aprime, ec.fieldOrder);

    // \f$b^{\prime} = 2 \cdot y_A\f$
    mpz_mul_ui(bprime, a.y, 2);
    mpz_mod(bprime, bprime, ec.fieldOrder);

    // \f$c = -b^{\prime} \cdot y_A - a^{\prime} \cdot x_A\f$
    mpz_neg(bAddInv, bprime);
    mpz_mod(bAddInv, bAddInv, ec.fieldOrder);
    mpz_mul(bAddInvyA, bAddInv, a.y);
    mpz_mod(bAddInvyA, bAddInvyA, ec.fieldOrder);
    mpz_mul(axA, aprime, a.x);
    mpz_mod(axA, axA, ec.fieldOrder);
    mpz_neg(axAaddInv, axA);
    mpz_mod(axAaddInv, axAaddInv, ec.fieldOrder);
    mpz_add(c, bAddInvyA, axAaddInv);
    mpz_mod(c, c, ec.fieldOrder);

    // Evaluation at \f$B\f$
    // Let \f$r\f$ denote the result:
    // \f$r = a^{\prime} \cdot x_B + b^{\prime} \cdot y_B + c\f$
    axB = complex_modMulScalar(b.x, aprime, ec.fieldOrder);
    byB = complex_modMulScalar(b.y, bprime, ec.fieldOrder);
    resultPart = complex_modAdd(axB, byB, ec.fieldOrder);
    *result = complex_modAddScalar(resultPart, c, ec.fieldOrder);

    complex_destroyMany(3, axB, byB, resultPart);
    mpz_clears(threeAddInv, minusThree, xasquared, aprime, bprime, bAddInv, bAddInvyA, axA, axAaddInv, c, NULL);
    return CRYPTID_SUCCESS;
}

CryptidStatus divisor_evaluateLine(Complex* result, const EllipticCurve ec, const AffinePoint a, const AffinePoint aprime, 
                            const ComplexAffinePoint b)
{
    // Implementation of Algorithm 3.4.3 in [RFC-5091].

    // Argument check
    if(complexAffine_isInfinity(b))
    {
        return CRYPTID_DIVISOR_OF_LINE_INFINITY_ERROR;
    }

    // Special cases
    if(affine_isInfinity(a))
    {
        *result = divisor_evaluateVertical(ec, aprime, b);
        return CRYPTID_SUCCESS;
    }

    AffinePoint aPlusAPrime;
    CryptidStatus status = affine_add(&aPlusAPrime, a, aprime, ec);
    if(status)
    {
        return status;
    }

    if(affine_isInfinity(aprime) || affine_isInfinity(aPlusAPrime))
    {
        *result = divisor_evaluateVertical(ec, a, b);
        affine_destroy(aPlusAPrime);
        return CRYPTID_SUCCESS;
    }
    affine_destroy(aPlusAPrime);

    if(affine_isEquals(a, aprime))
    {
        return divisor_evaluateTangent(result, ec, a, b);
    }

    mpz_t linea, lineb, linebaddinv, q, t, taddinv, linec;
    mpz_inits(linea, lineb, linebaddinv, q, t, taddinv, linec, NULL);
    Complex axb, byb, resultPart;

    // Line computation
    // \f$a = y_A^{\prime} - y_A^{\prime\prime}\f$
    mpz_sub(linea, a.y, aprime.y);
    mpz_mod(linea, linea, ec.fieldOrder);

    // \f$b = x_A^{\prime\prime} - x_A^{\prime}\f$
    mpz_sub(lineb, aprime.x, a.x);
    mpz_mod(lineb, lineb, ec.fieldOrder);

    // \f$c = -b \cdot y_A^{\prime} - a \cdot x_A^{\prime}\f$
    mpz_neg(linebaddinv, lineb);
    mpz_mod(linebaddinv, linebaddinv, ec.fieldOrder);
    mpz_mul(q, linebaddinv, a.y);
    mpz_mod(q, q, ec.fieldOrder);
    mpz_mul(t, linea, a.x);
    mpz_mod(t, t, ec.fieldOrder);
    mpz_neg(taddinv, t);
    mpz_mod(taddinv, taddinv, ec.fieldOrder);
    mpz_add(linec, q, taddinv);
    mpz_mod(linec, linec, ec.fieldOrder);

    // Evaluation at B
    // Let \f$r\f$ denote the result:
    // \f$r = a \cdot x_B + b \cdot y_B + c\f$
    axb = complex_modMulScalar(b.x, linea, ec.fieldOrder);
    byb = complex_modMulScalar(b.y, lineb, ec.fieldOrder);
    resultPart = complex_modAddScalar(byb, linec, ec.fieldOrder);
    *result = complex_modAdd(axb, resultPart, ec.fieldOrder);

    mpz_clears(linea, lineb, linebaddinv, q, t, taddinv, linec, NULL);
    complex_destroyMany(3, axb, byb, resultPart);

    return CRYPTID_SUCCESS;
}