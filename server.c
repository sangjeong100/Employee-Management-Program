/*
    사원 관리 프로그램 서버
    기능 : server - client 통신을 통한 사원 DB관리
    개발자 : 유상정
*/

#include "common.h"

#define ADMIN_LIST "./admin_data.csv" // 회원가입했을 때 기록되는 로그 파일

#define ADMIN_KEY "1011"              //ADMIN_KEY

int connection_status = TRUE;

BIO* server_bio, * client_bio, * out;                 //socket 통신
RSA* rsa_object = NULL;                 //rsa 암호 object



admin_info admin;                       //로그인 중인 admin 저장.

void Server();                          //server routine 시작
void secure_socket_init();                     //socket bind 함수
void connect_listen();                  //socket listen 함수
void server_ection();                       //로그인 성공한 후, routine

int main(int argc, char** argv)
{
    printf("server의 종료를 원하면 Ctrl + C 를 눌러주세요.\n");

    secure_socket_init();                      //secure socket 연결 함수 호출 

    while (1)
    {
        connect_listen();     //socket listen 함수

        connection_status = TRUE;

        Server();           //server routine

    }

    BIO_free(client_bio);
    BIO_free(server_bio);

    return 0;
}
void secure_write(BIO* socket_bio, char* buf, int buf_size)
{
    int plain_length;      //평문 길이
    int out_length = 0;        //CipherUpdate, CipherFinal 함수에서 out data 길이를 저장
    int cipher_length;       //암호문 길이

    char cipher[BUF_SIZE] = { 0, };   //암호문

    EVP_CIPHER_CTX* ctx;                //암호화 컨텍스트 -> 암호화 데이터의 정보 저장되는 구조체
    // EVP_CIPHER_CTX_init(ctx);

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        fprintf(stderr, "ctx new error!\n");
        exit(-1);
    }

    plain_length = strlen(buf);

    //AES 256 cbc 모드로 암호화 진행
    if ((EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) != 1)
    {
        fprintf(stderr, "EVP_EncryptInit error!\n");
        exit(-1);
    }

    if ((EVP_EncryptUpdate(ctx, cipher, &out_length, buf, plain_length)) != 1)
    {
        fprintf(stderr, "EVP_CipherUpdate error!\n");
        exit(-1);
    }

    cipher_length = out_length;

    if ((EVP_EncryptFinal_ex(ctx, cipher + out_length, &out_length)) != 1)
    {
        fprintf(stderr, "EV_EnctyptFinal error!\n");
        exit(-1);
    }
    cipher_length += out_length;
    cipher[cipher_length] = '\0';


    EVP_CIPHER_CTX_cleanup(ctx);
    //암호화 완료

    if ((BIO_write(socket_bio, cipher, BUF_SIZE)) <= 0)    //암호화된 data 전송
    {
        fprintf(stderr, "write error!\n");
        connection_status = FALSE;

        exit(-1);
    }
}

char* secure_read(BIO* socket_bio, char* buf, int buf_size)
{
    int cipher_length = 0; // 수신한 암호문의 길이
    int out_length = 0; // CipherUpdate, CipherFinal 함수에서 out 데이터 길이를 저장할 변수
    int plain_length = 0; // 평문 길이

    char plain[BUF_SIZE] = { 0, }; // 복호화한 데이터

    EVP_CIPHER_CTX* ctx; // EVP context 변수

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        fprintf(stderr, "ctx new error!\n");
        exit(-1);
    }

    memset(buf, 0, BUF_SIZE);        //buf 배열 초기화

    if ((BIO_read(socket_bio, buf, BUF_SIZE)) <= 0)  //암호화된 data 수신               
    {
        fprintf(stderr, "read error!\n");
        connection_status = FALSE;
        exit(-1);
    }
    cipher_length = strlen(buf);

    //AES-256 cbc 모드로 복호화 수행
    EVP_CIPHER_CTX_init(ctx);
    if ((EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) != 1)
    {
        fprintf(stderr, "EVP_DecryptInit error!\n");
        exit(-1);
    }
    if ((EVP_DecryptUpdate(ctx, plain, &out_length, buf, cipher_length)) != 1)
    {
        fprintf(stderr, "EVP_DecryptUpdate error!\n");
        exit(-1);
    }
    plain_length = out_length;

    EVP_DecryptFinal_ex(ctx, plain + out_length, &out_length);

    plain_length += out_length;
    plain[plain_length] = '\0';

    EVP_CIPHER_CTX_cleanup(ctx);
    // 복호화 수행 완료

    strcpy(buf, plain);

    return buf;
}

/*
    회원가입 routine
*/
int Sign_up()
{
    int key_count = 0;
    char admin_key[BUF_SIZE];
    admin_info sign_up_admin;

    printf("회원가입 요청을 받았습니다.\n");
    while (key_count < 5)
    {
        strcpy(admin_key, secure_read(client_bio, admin_key, BUF_SIZE));              //admin_key 입력 read

        if (!strcmp(ADMIN_KEY, admin_key))                                                //옳은 admin_key인지 확인
        {
            printf("Client에게 회원가입 자격을 부여합니다.\n");
            secure_write(client_bio, "회원가입 요청이 허용되었습니다.", BUF_SIZE);

            jmp_buf env;

            setjmp(env);                                                                //id 존재시, 돌아올 지점 setjmp

            //회원가입 id, pw, name 받음
            strcpy(sign_up_admin.id, secure_read(client_bio, sign_up_admin.id, BUF_SIZE));
            strcpy(sign_up_admin.pw, secure_read(client_bio, sign_up_admin.pw, BUF_SIZE));
            strcpy(sign_up_admin.name, secure_read(client_bio, sign_up_admin.name, BUF_SIZE));

            /*
                admin 파일에 회원가입된 admin 저장
            */
            int isExist = 0;
            FILE* admin_fp;
            if ((admin_fp = fopen(ADMIN_LIST, "a+b")) == NULL)
            {
                fprintf(stderr, "fopen error\n");
                exit(-1);
            }

            char tmp[3][BUF_SIZE];

            char str_tmp[BUF_SIZE];
            char* p;

            //같은 id가 있는지 검사
            while (!feof(admin_fp))
            {
                fgets(str_tmp, BUF_SIZE, admin_fp);

                p = strtok(str_tmp, ", \n");
                int cnt = 0;

                while (p != NULL)
                {
                    strcpy(tmp[cnt], p);
                    cnt++;
                    p = strtok(NULL, ", \n");
                }
                if (!strcmp(tmp[0], sign_up_admin.id))
                {
                    isExist = 1;
                    fclose(admin_fp);
                    break;
                }
            }


            if (isExist)                                                     //id 존재하면
            {
                secure_write(client_bio, "존재하는 ID입니다.", BUF_SIZE);
                printf("Client가 존재하는 ID를 입력하여 다시 입력 받습니다.\n");
                longjmp(env, 2);                                             //입력 다시받음
            }
            else
            {
                fprintf(admin_fp, "%s, %s, %s\n", sign_up_admin.id, sign_up_admin.pw, sign_up_admin.name);

                printf("전달받은 admin 정보를 등록합니다.\n");
                printf("********************\n");
                printf("admin_id : %s\n", sign_up_admin.id);
                printf("admin_name : %s\n", sign_up_admin.name);
                printf("********************\n");

                secure_write(client_bio, "Admin가입에 성공하셨습니다.", BUF_SIZE);
                fclose(admin_fp);
                break;
            }
        }
        else
        {
            printf("Client가 admin key를 틀렸습니다.\n");
            secure_write(client_bio, "admin key가 틀렸습니다.", BUF_SIZE);
            key_count++;
        }


    }


    if (key_count == 5)      //client가 admin key 5회 틀렸을 시, client는 강제종료 되어서 
        return 0;           //다시 client를 listening한다.
    else
        return 1;
}

int sign_in()
{

    admin_info sign_in_admin;
    int login_try = 0;

    while (login_try < 5)
    {

        strcpy(sign_in_admin.id, secure_read(client_bio, sign_in_admin.id, BUF_SIZE));
        strcpy(sign_in_admin.pw, secure_read(client_bio, sign_in_admin.pw, BUF_SIZE));

        FILE* admin_fp;
        if ((admin_fp = fopen(ADMIN_LIST, "rb")) == NULL)
        {
            fprintf(stderr, "fopen error\n");
            exit(-1);
        }


        char tmp[3][BUF_SIZE];
        char str_tmp[BUF_SIZE];
        char* p;
        int isExist = 0;

        //같은 id가 있는지 검사
        while (!feof(admin_fp))
        {
            fgets(str_tmp, BUF_SIZE, admin_fp);

            p = strtok(str_tmp, ", \n");
            int cnt = 0;

            while (p != NULL)
            {
                strcpy(tmp[cnt], p);
                cnt++;
                p = strtok(NULL, ", \n");
            }
            if (!strcmp(tmp[0], sign_in_admin.id))
            {
                isExist = 1;
                fclose(admin_fp);
                break;
            }
        }
        if (isExist)
        {
            if (!strcmp(tmp[1], sign_in_admin.pw))
            {
                printf("Client가 login에 성공하였습니다.\n");
                secure_write(client_bio, "login에 성공했습니다.", BUF_SIZE);

                admin = sign_in_admin;                  //로그인 성공한 admin 정보 저장

                strcpy(admin.name, tmp[2]);              //이름도 저장

                return 1;
            }
            else
            {
                login_try++;
                printf("Client가 잘못된 PW를 입력하였습니다.\n");
                secure_write(client_bio, "존재하지 않는 ID이거나 PW가 틀렸습니다.", BUF_SIZE);
                continue;
            }

        }
        else
        {
            login_try++;
            printf("Client가 존재하지 않는 ID를 입력하였습니다.\n");
            secure_write(client_bio, "존재하지 않는 ID이거나 PW가 틀렸습니다.", BUF_SIZE);
            continue;
        }


    }

    return 0;

}

void Employee_Registration()
{

}

void server_section()
{
    char section_mode[BUF_SIZE] = { 0, };

    while (1)
    {
        memset(section_mode, 0, BUF_SIZE);
        strcpy(section_mode, secure_read(client_bio, section_mode, sizeof(section_mode))); //client로 부터 mode 읽어옴
        printf("Section mode : %s\n", section_mode);

        if (!strcmp(section_mode, "employee registration"))
        {
            Employee_Registration();                        //사원 등록 구간
        }
    }
}

void Server()
{
    char mode[BUF_SIZE] = { 0, };

    while (1)
    {
        memset(mode, 0, BUF_SIZE);
        strcpy(mode, secure_read(client_bio, mode, sizeof(mode))); //client로 부터 mode 읽어옴
        printf("mode : %s\n", mode);

        if (!strcmp(mode, "sign_up")) {    //회원가입일시,
            printf("Sign_UP\n");
            if (!Sign_up())              //client 강제종료 당했으면 server routine 종료
                break;
        }
        else if (!strcmp(mode, "sign_in")) {//login 일 시,
            if (sign_in())
            {
                server_section();              //client가 로그인 성공 시.
            }
        }
        else if (!strcmp(mode, "exit")) {//프로그램 종료일때,

            printf("Client가 연결 종료를 요청하였습니다.\n");
            printf("Client와의 연결을 종료합니다.\n");

            break;

        }


    }

}


// socket 연결 함수
void secure_socket_init()
{
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    server_bio = BIO_new_accept(HOST_PORT); // 새로운 BIO 접근 만든다.


}
/*
    RSA key 생성 함수
*/
void RSA_key_generator(RSA** rsa_object, int bits)
{
    BIGNUM* e = NULL;
    // BIO *temp = NULL;
    e = BN_new();
    if (BN_set_word(e, RSA_F4) != 1)
    {
        fprintf(stderr, "BN_set_word error!\n");
        exit(-1);
    }

    *rsa_object = RSA_new();
    if (RSA_generate_key_ex(*rsa_object, 2048, e, NULL) != 1) // RSA 키 생성
    {
        BN_free(e);
        fprintf(stderr, "RSA key generate fail!\n");
        exit(-1);
    }

}

/*
    연결 listen함수이자, 키교환 이루어지는 함수
*/
void connect_listen()
{
    RSA_key_generator(&rsa_object, 2048);    //RSA key 생성

    printf("connection listening..\n");

    BIO_do_accept(server_bio);          //binding

    if (BIO_do_accept(server_bio) <= 0) // 클라이언트의 연결 요청을 기다림
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    char encrypted_key[BUF_SIZE] = { 0, };
    char encrypted_iv[BUF_SIZE] = { 0, };

    client_bio = BIO_pop(server_bio); // 접속이 완료되면 이 부분 통과(accept부분)
    printf("Client Connected, send public key to client...\n");

    int n = 0;
    n = PEM_write_bio_RSA_PUBKEY(client_bio, rsa_object); // 공개키를 클라이언트에게 전송

    sleep(1);

    n = BIO_read(client_bio, encrypted_key, BUF_SIZE); // 클라이언트로부터 공개키로 암호화한 AES Key를 수신함

    RSA_private_decrypt(n, encrypted_key, aes_key, rsa_object, RSA_PKCS1_OAEP_PADDING); // 개인키로 암호화된 AES Key를 복호화함


    printf("Recieved Symmetric Key : ");
    for (int i = 0; i < 32; i++)
        printf("%02X ", (unsigned char)aes_key[i]); // 복호화된 AES Key를 출력함
    printf("\n");

    n = BIO_read(client_bio, encrypted_iv, BUF_SIZE); // 클라이언트로부터 공개키로 암호화한 AES iv를 수신함

    RSA_private_decrypt(n, encrypted_iv, iv, rsa_object, RSA_PKCS1_OAEP_PADDING); // 개인키로 암호화된 AES iv를 복호화함

    printf("Recieved AES iv : ");
    for (int i = 0; i < 16; i++)
        printf("%02X ", (unsigned char)iv[i]); // 복호화된 AES iv를 출력함
    printf("\n");

    // 키 교환 완료. AES 암호화 통신 시작

    RSA_free(rsa_object);   //rsa 는 안씀으로 free


}