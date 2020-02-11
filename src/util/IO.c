#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/Utils.h"
#include "util/IO.h"

const int BASE = 10;

void writePublicParToFiles(PublicParameters* publicParameters)
{
    FILE * fp;
    struct stat st = {0};

    if (stat("./PP", &st) == -1) {
        mkdir("./PP", 0700);
    }

    fp = fopen ("PP/PP","w+");
    if (fp != NULL)
    {
        gmp_fprintf(fp, "%Zd\n%Zd\n%Zd\n%Zd\n%Zd\n%Zd\n%Zd\n%Zd\n", publicParameters->ellipticCurve.a, publicParameters->ellipticCurve.b, publicParameters->ellipticCurve.fieldOrder, publicParameters->q, publicParameters->pointP.x, publicParameters->pointP.y, publicParameters->pointPpublic.x, publicParameters->pointPpublic.y);
        fclose(fp);
    }


    fp = fopen ("PP/PP.hashf","wb");
    if (fp != NULL) {

        fwrite(&publicParameters->hashFunction, sizeof(publicParameters->hashFunction), 1, fp);

        fclose(fp);
    }

}

void writeCipherTextToFiles(CipherTextTuple* ciphertext)
{
    FILE * fp;
    struct stat st = {0};

    if (stat("./CT", &st) == -1) {
        mkdir("./CT", 0700);
    }


    fp = fopen ("CT/cipher","wb");
    if (fp != NULL) {

	fprintf(fp, "%zd\n%s\n%zd\n%s", ciphertext->cipherVLength, ciphertext->cipherV, ciphertext->cipherWLength, ciphertext->cipherW);

        fclose(fp);
    }
    printf("beleirt:\n");
    printf("VLength: %zd\n", ciphertext->cipherVLength);
    printf("%s\n", ciphertext->cipherV);
    printf("%zd\n", ciphertext->cipherWLength);
    printf("%s\n", ciphertext->cipherW);

    fp = fopen ("CT/cipherU","w+");
    if (fp != NULL) {
        gmp_fprintf(fp, "%Zd\n%Zd\n", ciphertext->cipherU.x, ciphertext->cipherU.y);
        fclose(fp);
    }

}

void writePrivateKeyToFiles(AffinePoint privateKey)
{
    FILE * fp;
    struct stat st = {0};

    if (stat("./PK", &st) == -1) {
        mkdir("./PK", 0700);
    }


    fp = fopen ("PK/private","w+");
    if (fp != NULL) {
        gmp_fprintf(fp, "%Zd\n%Zd\n", privateKey.x, privateKey.y);
        fclose(fp);
    }
}

PublicParameters readPublicParFromFile()
{
    FILE * fp;

    PublicParameters publicParameters;

    mpz_t a, b, fieldOrder, q, px, py, ppx, ppy;
    mpz_inits(a, b, fieldOrder, q, px, py, ppx, ppy, NULL);

    fp = fopen ("PP/PP","r");
    if (fp != NULL)
    {
        gmp_fscanf(fp, "%Zd\n%Zd\n%Zd\n%Zd\n%Zd\n%Zd\n%Zd\n%Zd\n", &a, &b, &fieldOrder, &q, &px, &py, &ppx, &ppy);
        fclose(fp);
    }

    publicParameters.ellipticCurve = ellipticCurve_init(a, b, fieldOrder);
    mpz_init(publicParameters.q);
    mpz_set(publicParameters.q, q);
    publicParameters.pointP = affine_init(px, py);
    publicParameters.pointPpublic = affine_init(ppx, ppy);

    fp = fopen ("PP/PP.hashf","r");
    if (fp != NULL)
    {
        int i = 0;
        fread(&i, sizeof(int), 1, fp);
        publicParameters.hashFunction = (HashFunction) i;
        fclose(fp);
    }

    return publicParameters;
}

AffinePoint readPrivateKeyFromFiles()
{
    AffinePoint privateKey;
    mpz_t x, y;
    mpz_inits(x, y, NULL);

    FILE * fp;
    fp = fopen ("PK/private","r");
    if (fp != NULL)
    {
        gmp_fscanf(fp,"%Zd\n%Zd\n", &x, &y);
        fclose(fp);
    }
    else printf("Can't open file");

    privateKey = affine_init(x, y);


    return privateKey;
}

CipherTextTuple readCipherTextFromFile()
{
    CipherTextTuple ciphertext;
    size_t cipherVLength, cipherWLength;
    unsigned char  cipherV[50], cipherW[50];

    FILE * fp;

    fp = fopen("CT/cipher", "rb");
    if (fp != NULL) {
	fscanf(fp, "%zd\n%s\n%zd\n%s", &cipherVLength, cipherV, &cipherWLength, cipherW);
        fclose(fp);
    }
    else printf("Can't open file");
    printf("%zd\n%s\n%zd\n%s\n", cipherVLength, cipherV, cipherWLength, cipherW);

    mpz_t x, y;
    mpz_inits(x, y, NULL);
    fp = fopen ("CT/cipherU","r");
    if (fp != NULL) {
        gmp_fscanf(fp,"%Zd\n%Zd\n", &x, &y);
        fclose(fp);
    }
    ciphertext = cipherTextTuple_init(affine_init(x, y), cipherV, cipherVLength, cipherW, cipherWLength);

    return ciphertext;
}
