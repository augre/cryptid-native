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
    const char *identity = "darth.plagueis@sith.com";
    const char *message;
    int fp = open ("message", O_RDONLY);
    
    int len = lseek(fp, 0, SEEK_END);
    message = mmap(0, len, PROT_READ, MAP_PRIVATE, fp, 0);
    close(fp);

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
