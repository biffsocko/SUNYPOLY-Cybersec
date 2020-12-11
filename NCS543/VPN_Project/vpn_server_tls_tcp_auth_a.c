/************************************************************
 * Tom Murphy
 * vpn_server_tls_tcp_auth_a.c
 *
 COMPILE:
 *  gcc -o vpn_server_tls_tcp_auth_a  vpn_server_tls_tcp_auth_a.c -lssl -lcrypto -lcrypt
 *
 * VPN project Fall 2020
 ************************************************************/
 
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <shadow.h>
#include <crypt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.17"
#define BUFF_SIZE 2000
#define BACKLOG 200

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }   
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

#define DEBUG 0




/******************************** 
 * some global variables 
 * i know .. this is bad.
 ********************************/
struct sockaddr_in peerAddr;
int tunfd, sockfd,tlsfd;
int accept_sd;                         
int alen;        
int err;
SSL_METHOD *meth;
SSL_CTX* ctx;
SSL *ssl;
int error_msg;
int acpterr;
int ret;





/*****************************************************************************
 * closer()
 * this will take care of closing up the master socket descriptor upon
 * SIGINT or other signals.  Eventually, this will also log termination
 * errors to syslog
 *****************************************************************************/
void closer(int SIGX){
        printf("exiting on Signal %d\n", SIGX);
        close(sockfd);
        exit(99);
}


/*****************************************************************************
 * createTunDevice()
 * creates the tunnel device .. add some stuff for routing here later
 *****************************************************************************/
int createTunDevice()
{
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);      

   if(DEBUG == 1 ){
       printf("running ifconfig\n");   
   }

   system("/sbin/ifconfig tun0 10.4.2.5/24 up");
   
   if(DEBUG == 1 ){
       printf("running route\n");   
   }
   
   system("route add -net 10.4.2.0/24 tun0");


   return tunfd;
}

void tunSelected(int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    //printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    
    if(DEBUG == 1 ){
        printf("tunSelected() - buff = %s\n",buff);
    }

    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
    //                sizeof(peerAddr));
     SSL_write(ssl,buff,len);
}

void socketSelected (int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    if(DEBUG == 1 ){
        printf("Got a packet from the tunnel\n");
    }

    bzero(buff, BUFF_SIZE);
    //len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    len = SSL_read(ssl, buff, BUFF_SIZE);

    if(DEBUG == 1 ){
        printf("socketSelected() - buff = %s\n",buff);
    }

    write(tunfd, buff, len);
}

/*****************************************************************************
 * processRequest(SSL* ssl, int sock)
 * do something!
 *****************************************************************************/
void processRequest(SSL* ssl, int sock)
{
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    printf("Received: %s\n",buf);

    // Construct and send the HTML page
    char *html =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<!DOCTYPE html><html>"
        "<head><title>Hello World</title></head>"
        "<style>body {background-color: black}"
        "h1 {font-size:3cm; text-align: center; color: white;"
        "text-shadow: 0 0 3mm yellow}</style></head>"
        "<body><h1>Hello, world!</h1></body></html>";
    SSL_write(ssl, html, strlen(html));
    SSL_shutdown(ssl);  SSL_free(ssl);
}


/*****************************************************************************
 * userauth()
 * does user authentication via /etc/shadow
 *****************************************************************************/
int userauth(char *u, char *p){
    struct spwd *pw;
    char *epasswd;
    
    pw = getspnam(u);
    if (pw == NULL) {
       printf("failed on getspname()\n");
       return 1;
    }

    if(DEBUG == 1){
        printf("Login name: %s\n", pw->sp_namp);
        printf("Passwd : %s\n", pw->sp_pwdp);
        printf("passwd from term = %s\n",p);
    }

    epasswd = crypt(p, pw->sp_pwdp);

    if(DEBUG == 1){
        printf("%s\n",epasswd);
    }

    if (strcmp(epasswd, pw->sp_pwdp)) {
        return 1;
    }else{
        return 0;
    }
}

/*****************************************************************************
 * doTLS()
 * all the TLS wizadry happens here
 *****************************************************************************/
int doTLS(int sock){

    /*********************************************************
     * Step 0: OpenSSL library initialization
     *  This step is no longer needed as of version 1.1.0.
     *********************************************************/
    if(DEBUG==1){
        printf("starting SSL_library_init\n");
    }
    SSL_library_init();

    if(DEBUG ==1){
        printf("starting SSL_load_error_strings\n");
    }
    SSL_load_error_strings();

    if(DEBUG == 1){
        printf("starting SSLeay_add_ssl_algorithms\n");
    }
    SSLeay_add_ssl_algorithms();

    /*********************************************************
     * Step 1: SSL context initialization
     *********************************************************/
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /*********************************************************
     * Step 2: Set up the server certificate and private key
     *********************************************************/
    printf("setting up certs and keys\n");

    if(SSL_CTX_use_certificate_file(ctx, "/root/VPN/tls/certs/TomMurphyserver.crt", SSL_FILETYPE_PEM) != 1){
         printf("error loading /root/VPN/tls/certs/TomMurphyserver.crt\n");
         exit(1);
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, "/root/VPN/tls/certs/TomMurphyserver.key", SSL_FILETYPE_PEM) != 1){
       printf("error loading /root/VPN/tls/certs/TomMurphyserver.key\n");
       exit(1);
    }

    /*********************************************************
     * Step 3: Create a new SSL structure for a connection
     *********************************************************/
    ssl = SSL_new (ctx);
    if(ssl == NULL){
        printf("error creating ssl object .. exiting\n");
        exit(1);
    }
   
    if(SSL_set_fd (ssl, sock) != 1){
           printf("error on SSL_set_fd .. exiting\n");
           exit(1);
       }

    error_msg = SSL_accept (ssl);

    if(error_msg < 1){
          /*************************************************
           * well, if we made it here - we failed at making
           * an ssl connection.  Don't worry - chin up.  
           * let's make the best of a bad situation and 
           * try to figure out what happened to avoid 
           * this happening again.  Strive to be better
           *************************************************/
          printf("SSL_accept failed - err = %d\n",error_msg);
          switch (SSL_get_error (ssl, error_msg)){
                case SSL_ERROR_NONE:             printf("SSL_ERROR_NONE\n");
                                                 break;
                case SSL_ERROR_WANT_WRITE:       printf("SSL_ERROR_WANT_WRITE\n");
                                                 break;
                case SSL_ERROR_WANT_READ:        printf("SSL_ERROR_WANT_READ\n");
                                                 break;
                case SSL_ERROR_WANT_X509_LOOKUP: printf("SSL_ERROR_WANT_X509_LOOKUP:\n");
                                                 break;
                case SSL_ERROR_SYSCALL:          printf("SSL_ERROR_SYSCALL\n");
                                                 printf("ERR_get_error returns %lu\n",ERR_get_error());
                                                 break;
                case SSL_ERROR_SSL:              printf("SSL_ERROR_SSL\n");
                                                 break;
                case SSL_ERROR_ZERO_RETURN:      printf("SSL_ERROR_ZERO_RETURN\n");
                                                 break;
             }
          exit (1);
      }
      CHK_SSL(error_msg);
      /********************************************
       * we made it! SSL is working now
       ********************************************/
      printf ("SSL connection established!\n");
      return(sock);
}






/*****************************************************************************
 * initTCPServer()
 * take care of incoming TCP connections here
 *****************************************************************************/
int initTCPServer() {
    int sockfd;
    struct sockaddr_in server;
    char buff[100];
    int err;
    int acpterr;
    int ret;
    char user[1024];
    char pass[1024];



    /*
     * set up the socket stuff
     */
    printf("starting TCP server\n");
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);
    
    /* create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(DEBUG == 1){
        printf("got sockfd\n");
    }

    /* bind to the port */
    bind(sockfd, (struct sockaddr*) &server, sizeof(server));
    if(DEBUG == 1){
        printf("binded sockfd\n");
    }

    /*****************************************************************************
     * listen to the port
     *****************************************************************************/
    if((listen(sockfd, BACKLOG)) == -1){
            fprintf(stderr, "vpn_server_tcp unable to listen to port. exiting\n");
            close(sockfd);
            exit(4);
    }

    if(DEBUG ==1){
        printf("listening on the port\n");
    }
    /*****************************************************************************
     * clean up runaway processes & catch signals for closing out nicely
     *****************************************************************************/
     signal(SIGCHLD, SIG_IGN);
     signal(SIGINT, closer);


    while(1){
        alen=sizeof(server);
        if(!(accept_sd=accept(sockfd, (struct sockaddr *) &server, &alen))){
                /* oh snap */
                fprintf(stderr, "vpn_server_tcp is unable to accept connections. exiting\n");
                close(sockfd);
                exit(5);
        }

        // tlsfd=doTLS(accept_sd);
        printf("open for business\n");

        /* fork off */
        switch(fork()){
        case 0:                         /* child process */
                   if(DEBUG == 1){
                       printf("forked\n");
                   }

                   tlsfd=doTLS(accept_sd);
                   printf("created ssl connection\n");

                   /*****************************************************************
                    * user authentication 
                    *****************************************************************/
                   SSL_write(ssl, "enter your username\n",1024);
                   SSL_read(ssl,user,1024);
                   if(DEBUG == 1){
                       printf("%s\n",user);
                   }

                   SSL_write(ssl, "enter your password\n",1024);
                   SSL_read(ssl,pass,1024);
                   if(DEBUG == 1){
                       printf("%s\n",pass); 
                   }
 
                   if(userauth(user,pass) == 1){
                       printf("user authentication failed .. exiting\n");
                       SSL_write(ssl,"user auth failed.  Exiting",1024);
                       close(tlsfd);
                       close(accept_sd);
                       exit(1);
                   }
                   printf("user has authorized\n");
                   /****************************************************
                    * make stuff happen here
                    *****************************************************/
                    while (1) {
                        //sleep(6);
                        if(DEBUG > 2){
                            printf("in the second loop\n");
                        }
                        fd_set readFDSet;
                        FD_ZERO(&readFDSet);
                        FD_SET(tlsfd, &readFDSet);
                        //FD_SET(tunfd, &readFDSet);
                        FD_SET(tunfd, &readFDSet);
                        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
                        if (FD_ISSET(tunfd,  &readFDSet)){ 
                            if(DEBUG > 0){
                                printf("calling tunnelSelected\n");
                                SSL_write(ssl,"tunnelSelected",20);
                            }
                            tunSelected(tunfd, tlsfd);
                        }
                        if (FD_ISSET(tlsfd, &readFDSet)){
                            if(DEBUG > 0){
                                printf("calling socketSelected\n");
                                SSL_write(ssl,"socketSelected",20);
                            }
                            socketSelected(tunfd, tlsfd);
                        }
                    }

                    (void) close(accept_sd);
                    (void) close(tlsfd);
                    
                    exit(0);
        default:                        /* parent process */
                        close(accept_sd);
                        break;
        case -1:
                        fprintf(stderr, "vpn_server_tcp error forking child\n");
                        break;
        } 
    }
}


int main (int argc, char * argv[]) {
   tunfd  = createTunDevice();
   sockfd = initTCPServer();
   exit(0);
}


