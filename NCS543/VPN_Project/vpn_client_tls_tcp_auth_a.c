/**************************************************************
 * Tom Murphy
 * vpn_client_tls_tcp_auth_a.c
 * 
 * vpn client program for final project.
 * COMPILE:
 *  gcc -o vpn_client_tls_tcp_auth_a  vpn_client_tls_tcp_auth_a.c -lssl -lcrypto -lcrypt
 *
 * runme like:
 * vpn_client_tls_tcp_auth_a <name on SSL cert> <port> <vpnserver name>
 *   ex: vpn_client_tls_tcp_auth_a sunypoly.edu 55555 vpnserver.com
 ***************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
//#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include<sys/types.h>


#include <openssl/ssl.h>
#include <openssl/err.h>


#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "/root/VPN/tls/certs"

#define DEBUG 0

#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.17"
#define BUFF_SIZE 2000
struct sockaddr_in peerAddr;
SSL_METHOD *meth;
SSL_CTX* ctx;
SSL* ssl;


/**********************************************************************
 * verify_callback()
 **********************************************************************/
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

/**********************************************************************
 * setupTLSClient()
 **********************************************************************/
SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   //SSL_METHOD *meth;
   //SSL_CTX* ctx;
   //SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
        printf("Error setting the verify locations. \n");
        exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}

/**********************************************************************
 * getIP()
 **********************************************************************/
char * getIP(char *hostname){
    struct addrinfo hints, *result;
    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET; // AF_INET means IPv4 only addresses
    int error = getaddrinfo(hostname, NULL, &hints, &result);
    if (error) {
        printf("wtf\n");
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        exit(1);
    }
    // The result may contain a list of IP address; we take the first one.
    struct sockaddr_in* ip = (struct sockaddr_in *) result->ai_addr;
    printf("IP Address: %s\n", (char *)inet_ntoa(ip->sin_addr));
    freeaddrinfo(result);
    return (char *)inet_ntoa(ip->sin_addr);
}

/**********************************************************************
 * createTunDevice
 * sets up tunnel interface - does some routes
 **********************************************************************/
int createTunDevice()
{
    int tunfd;
    int err;
    struct ifreq ifr;
    char *devname = "tun0";
    memset(&ifr, 0, sizeof(ifr));


   /*******************************************************
    * Flags: IFF_TUN   - TUN device (no Ethernet headers)
    *        IFF_TAP   - TAP device
    *
    *        IFF_NO_PI - Do not provide packet information
    *******************************************************/
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);

    if(DEBUG == 1){
       printf("tund fd = %d\n",tunfd);
    }

   /*******************************************************
    * run shell commands to start tunel network stuff
    * I should probably find a better way to do this
    *******************************************************/
   system("/sbin/ifconfig tun0 10.4.2.99/24 up");
   system("/sbin/route add -net 10.4.2.0/24 tun0");
   system("/sbin/route add -net 192.168.1.0/24 gw 10.4.2.5 tun0");

   return tunfd;
}

/**********************************************************************
 * connectToTCPServer()
 **********************************************************************/
int connectToTCPServer(char *server_ip){
    int sockfd;
    int ret;
 
    printf("entering connectToTCPServer\n");

    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    //peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    peerAddr.sin_addr.s_addr = inet_addr(server_ip);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    ret = connect(sockfd, (struct sockaddr*)&peerAddr, sizeof(peerAddr));
    if (ret == -1) {
	perror("connect");
	return -1;
    }

    if(DEBUG == 1){
        printf("have sockfd now\n");
    }

    return sockfd;
}



void tunSelected(int tunfd, int sockfd){
    int  len;
    size_t bytes_sent;
    char buff[BUFF_SIZE];
    char *hello="Hello";


    if(DEBUG==1){
        printf("Got a packet from TUN (tunSelected Function)\n");
    }

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);

    if(DEBUG == 1){
        printf("TUN buf : %s\n",buff);
        printf("TUN len : %d\n",len);
    }

    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,sizeof(peerAddr));
    SSL_write(ssl, buff, len);

    if(DEBUG == 1){ 
        printf("sent buff to ssl\n");
    }
}

void socketSelected (int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    //printf("Got a packet from the tunnel\n");
    //printf("SOCK buf: %s\n",buff);

    bzero(buff, BUFF_SIZE);
    //len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    len = SSL_read(ssl, buff, BUFF_SIZE);
    write(tunfd, buff, len);
}


int main (int argc, char * argv[]) {
   int tunfd, sockfd;
   char *hostname = "yahoo.com";
   int port = 443;
   char str[1024];
   char *ip;
   char *vpnhost;



   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);
   if (argc > 3) vpnhost = argv[3];

   printf("%s\n",vpnhost);

   ip = getIP(vpnhost);
   /********************************************************
    * Network and Tunnel magic
    ********************************************************/
   tunfd  = createTunDevice();
   sockfd = connectToTCPServer(ip);
   printf("returned to main function again\n");

   /********************************************************
    * TLS initialization
    ********************************************************/
   SSL *ssl   = setupTLSClient(hostname);

   /********************************************************
    * TLS handshake
    ********************************************************/
    SSL_set_fd(ssl, sockfd);
    if(DEBUG ==1){
        printf("ssl socket created - sockfd = %d\n",sockfd);
    }
    int err = SSL_connect(ssl); //CHK_SSL(err);
    if(DEBUG == 1){
        printf("err = %d\n",err);
    }
    switch (SSL_get_error (ssl, err)){
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

    CHK_SSL(err);
    if(DEBUG == 1){
       printf("chkssl err = %d\n",err);
    }
    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(ssl));


   /********************************************************
    * user autherization
    ********************************************************/
    SSL_read(ssl, str, 1024);
    printf("%s\n",str);
    SSL_write(ssl,"seed",1024);

    memset(str,0,1024);

    SSL_read(ssl, str, 1024);
    printf("%s\n",str);
    SSL_write(ssl,"dees",1024);

   /********************************************************
    * Send/Receive data 
    ********************************************************/
   char buf[9000];
   char sendBuf[200];
   sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
   SSL_write(ssl, sendBuf, strlen(sendBuf));

   int len;
   do {
     len = SSL_read (ssl, buf, sizeof(buf) - 1);
     buf[len] = '\0';
     printf("%s\n",buf);
     len=0;
   } while (len > 0);


   while (1) {
     fd_set readFDSet;
     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)){ 
         if(DEBUG > 1){
             printf("client tunnelSelected\n");
         }
         tunSelected(tunfd, sockfd);
     }
     if (FD_ISSET(sockfd, &readFDSet)){ 
         if(DEBUG > 1){ 
              printf("client socketSelected\n");
         }
         socketSelected(tunfd, sockfd);
     }
 
  }
}


