#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmp.h"

#include "CryptID.h"
#include "util/Validation.h"
#include "util/Utils.h"
#include "util/IO.h"


int main()
{
    const char *message = "Ironic.";
    const char *identity = "darth.plagueis@sith.com";


    PublicParameters publicParameters = readPublicParFromFile();
    (validation_isPublicParametersValid(publicParameters)) ? (printf("PublicParameters valid\n")) : (printf("PublicParameters  invalid\n"));

    CipherTextTuple* ciphertext = malloc(sizeof (CipherTextTuple));
    if (CRYPTID_SUCCESS != cryptid_encrypt(ciphertext, message, strlen(message), identity, strlen(identity), publicParameters))
    {
        printf("Encrypt failed\n");
        return -1;
    }
    writeCipherTextToFiles(ciphertext);

    return 0;
}
