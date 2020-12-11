    /*  vulp.c  */

    #include <stdio.h>
    #include <unistd.h>
    #include <string.h>
    #include <stdlib.h>


    int main()
    {
       char * fn = "/tmp/XYZ";
       char buffer[60];
       FILE *fp;

       uid_t realUID = getuid();
       uid_t effective_UID = geteuid();

       seteuid(realUID); 
       /* get user input */
       scanf("%50s", buffer );

       if(!access(fn, W_OK)){

            fp = fopen(fn, "a+");
            fwrite("\n", sizeof(char), 1, fp);
            fwrite(buffer, sizeof(char), strlen(buffer), fp);
            fclose(fp);
            setuid(effective_UID);
       }
       else printf("No permission \n");
    }
