#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "gmp.h"

#include "CryptID.h"
#include "util/Validation.h"
#include "util/Utils.h"
#include "util/IO.h"


int main()
{
    //FILE * fp;
    const char *message;
    int fp = open ("message", O_RDONLY);
//    if (fp != NULL)
//    {
        int len = lseek(fp, 0, SEEK_END);
        message = mmap(0, len, PROT_READ, MAP_PRIVATE, fp, 0);
        close(fp);
//        fclose(fp);
//    }
    const char *identity = "darth.plagueis@sith.com";

    PublicParameters* publicParameters = malloc(sizeof (PublicParameters));
    mpz_t masterSecret;
    mpz_init(masterSecret);
    mpz_init(publicParameters->q);
    if (CRYPTID_SUCCESS != cryptid_setup(LOWEST, publicParameters, masterSecret))
    {
        printf("Setup failed\n");
        return -1;
    }

    CipherTextTuple* ciphertext = malloc(sizeof (CipherTextTuple));
    if (CRYPTID_SUCCESS != cryptid_encrypt(ciphertext, message, strlen(message), identity, strlen(identity), *publicParameters))
    {
        printf("Encrypt failed\n");
        return -1;
    }

    AffinePoint privateKey;
    if (CRYPTID_SUCCESS != cryptid_extract(&privateKey, identity, strlen(identity), *publicParameters, masterSecret))
    {
        printf("Extract failed\n");
        return -1;
    }

    writeCipherTextToFiles(ciphertext);
    writePublicParToFiles(publicParameters);
    writePrivateKeyToFiles(privateKey);

    affine_destroy(privateKey);
    mpz_clears(publicParameters->q, masterSecret, NULL);
    affine_destroy(publicParameters->pointP);
    affine_destroy(publicParameters->pointPpublic);
    ellipticCurve_destroy(publicParameters->ellipticCurve);
    free(publicParameters);

    return 0;

}
