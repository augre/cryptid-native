#ifndef __CRYPTID_PUBLICPARAMETERS_H
#define __CRYPTID_PUBLICPARAMETERS_H

#include "gmp.h"

#include "elliptic/AffinePoint.h"
#include "elliptic/EllipticCurve.h"
#include "identity-based/HashFunction.h"


// References
//  * [RFC-5091] Xavier Boyen, Luther Martin. 2007. RFC 5091. Identity-Based Cryptography Standard (IBCS) #1: Supersingular Curve Implementations of the BF and BB1 Cryptosystems


/**
 * Struct storing the IBE Public Parameters. Corresponds to {@code BFPublicParameters} in [RFC-5091].
 */
typedef struct PublicParameters
{
    /**
     * The Type-1 elliptic curve we're operating over. Note, that the {@code p} field of {@code BFPublicParameters}
     * corresponds to {@code ellipticCurve.fieldOrder}.
     */
    EllipticCurve ellipticCurve;

    /**
     * Subgroup order.
     */
    mpz_t q;

    /**
     * A point in \f$E(F_p)\f$.
     */
    AffinePoint pointP;

    /**
     * A point in \f$E(F_p)\f$.
     */
    AffinePoint pointPpublic;

    /**
     * The used hash function.
     */
    HashFunction hashFunction;
} PublicParameters;

#endif
