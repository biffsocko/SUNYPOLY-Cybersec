/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

#define DEBUG 0

void printBN(char *msg, BIGNUM * a){
   /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */

   char * number_str = BN_bn2hex(a);
   printf("%s %s\n", msg, number_str);
   OPENSSL_free(number_str);
}

int main (){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM  *n, *d, *e, *m, *c, *tmp;
    BIGNUM *message;
    message = BN_new(); 
    c=BN_new();
    n=BN_new();
    m=BN_new();
    d=BN_new();
    e=BN_new();
    c=BN_new();
    tmp=BN_new();
     
    
    //initialize message "A top secret"
    //BN_hex2bn(&message, "49206f776520796f75202433303030");    //  text I owe you $3000
    BN_hex2bn(&message, "ab5eb79ca4815af9e8266fa188238ba60d8b1c7b7d5f555b0da3505c659468de");    //  text I owe you $3000

    BN_hex2bn(&d,"B9E0CB10D4AF76BDD49362EB3064B881086CC304D962178E2FFF3E65CF8FCE62E63C521CDA16454B55AB786B63836290CE0F696C99C81A148B4CCC4533EA88DC9EA3AF2BFE80619D7957C4CF2EF43F303C5D47FC9A16BCC3379641518E114B54F828BED08CBEF030381EF3B026F86647636DDE7126478F384753D1461DB4E3DC00EA45ACBDBC71D9AA6F00DBDBCD303A794F5F4C47F81DEF5BC2C49D603BB1B24391D8A4334EEAB3D6274FAD258AA5C6F4D5D0A6AE7405645788B54455D42D2A3A3EF8B8BDE9320A029464C4163A50F14AAEE77933AF0C20077FE8DF0439C269026C6352FA77C11BC87487C8B993185054354B694EBC3BD3492E1FDCC1D252FB");

    BN_hex2bn(&n,"9744ff3b70780988cf7d56becbebe352a2da13101c9f3b6869aea052aaeb6542c36a42edc5221a9fbac130eebea16272ed44b7aabdcd12d036c1da988dc14c16001882368e47cdc26650e0bf464a28cba94484dde136ef5d09f6174204911524c164010004374f0fe7e034973453184e3057a8855cf0f627f953725fa61ce594953622d0f60fb4072b6a813c5cfe421447029656af04d9e7286aa959a04ecd4504ad0b4f8657267a2be2249e1999c58334e08abf83b8704da498298aae4a08eb727eb1d37b45bb65cc17e2f9a72d4a0da45ac0a1cd5bbe9399ad6d48e968bf8e1abab400b37144b93aa3425a745dc959e97ad47c206f04aee9acf73a85464e90");

    //BN_hex2bn(&e,"65537");
    BN_hex2bn(&e,"10001");

//hash ab5eb79ca4815af9e8266fa188238ba60d8b1c7b7d5f555b0da3505c659468de

    if(DEBUG > 0){
        printBN("message = ", message); 
        printBN("d = ", d);
        printBN("n = ", n); 
        printBN("e = ", e); 
        printBN("c = ", c); 
     }

     BN_mod_exp(c,message,e,n,ctx);
     //BN_mod_exp(c,message,d,n,ctx);
     printBN("encryption result: ",c);

     printf("\n\n");

     BN_mod_exp(m,c,d,n,ctx);
     //BN_mod_exp(m,c,e,n,ctx);
     printBN("decryption result: ",m);

 
    return 0;
}
