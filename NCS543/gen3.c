#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define LEN 32 // 256 bits
#define KEYSIZE 16


void main(){

    unsigned char *key = (unsigned char *) malloc(sizeof(unsigned char)*LEN);
    FILE* random = fopen("/dev/urandom", "r");
    char prtkey;
    int i;

    fread(key, sizeof(unsigned char)*LEN, 1, random);
    fclose(random);

    uint8_t tid = atoi(key);
    printf("%d\n",tid); 




    printf("\n");
}
