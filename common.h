#include <sys/socket.h>     //socket include
#include <netinet/in.h>     //socket include 
#include <arpa/inet.h>      //socket include 
#include <netdb.h>          //socket include 

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/types.h>
#include <unistd.h>

#include <setjmp.h>         //setjmp 사용
#include <signal.h>          //signal 처리

#include <assert.h>         //error 처리 함수

//암호화 관련 include
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define BUF_SIZE 4096
#define TRUE    1
#define FALSE   0

unsigned char aes_key[BUF_SIZE]; // 키 공유할 변수
unsigned char iv[BUF_SIZE];

typedef struct admin_info {
    char id[BUF_SIZE];
    char pw[BUF_SIZE];
    char name[BUF_SIZE];
}admin_info;

char buf[BUF_SIZE];

#define HOST_PORT "127.0.0.1:8888"


void secure_write(BIO* socket_bio, char* buf, int buf_size);  //write 및 암호화
char* secure_read(BIO* socket_bio, char* buf, int buf_size);  //read 및 복호화