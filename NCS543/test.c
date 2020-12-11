#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>


int main() {

   FILE *fd = fopen("/dev/urandom","r");

    char buffer[32];
    //int error =  read(fd,buffer,sizeof(buffer) );

    if( fgets (buffer,sizeof(buffer), fd)!=NULL ) {
          /* writing content to stdout */
          puts(buffer);
             }
   fclose(fd);


    uint8_t tid = atoi(buffer);
    printf("%d\n",tid); 

    return 0;
}
