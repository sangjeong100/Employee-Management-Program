/*
    사원 관리 프로그램 클라이언트
    기능 : server - client 통신을 통한 사원 DB관리
    개발자 : 유상정
*/

#include "common.h"

#include <sys/signal.h> //alarm 사용
#include <setjmp.h>     //setjmp 사용
#include <termio.h>     //getch() 함수 구현
#include <term.h>       //getch() 함수 구현


BIO* socket_bio, * out;                    //통신 socket 

int connection_status;         //연결 상태 표시

admin_info admin;           //admin 정보                                                                

void Client();           //Client 함수
void secure_socket_init();         //socket 연결 함수

int main(int argc, char** argv)
{

    secure_socket_init();          //socket 연결 함수 호출
    printf("connected!\n");

    Client();



    BIO_free(socket_bio);

    return 0;

}

void secure_socket_init()
{
    RSA* rsa_pubkey = NULL;                //server의 RSA 공개키
    int n;

    ERR_load_crypto_strings();


    socket_bio = BIO_new_connect(HOST_PORT); //server와의 connection 생성(socket 생성)   

    printf("connecting..\n");
    if (BIO_do_connect(socket_bio) <= 0)     //connection 요청
    {
        //연결 실패 오류문 호출 후 client 종료
        fprintf(stderr, "connection error!\n");
        exit(-1);
    }

    connection_status = TRUE; //연결상태 표시

    printf("Connected!\n");
    printf("read RSA public key from server...\n");

    if ((BIO_read(socket_bio, buf, BUF_SIZE)) <= 0)    //server로부터 RSA 공개키 수신
    {
        fprintf(stderr, "read error!\n");
        exit(-1);
    }

    printf("\nRecieved Public key\n%s", buf); //공개키 출력

    BIO* bufiO = BIO_new_mem_buf(buf, -1);   //전달받은 public key를 memory mapping한다.
    BIO_set_flags(bufiO, BIO_FLAGS_BASE64_NO_NL);  //base 64로 encoding
    rsa_pubkey = PEM_read_bio_RSA_PUBKEY(bufiO, NULL, NULL, NULL); //mapping한 공개키를 rsa object로 읽는다.

    RAND_bytes(aes_key, 32);        //32byte의 AES key를 랜덤 생성 (AES-256 mode)
    printf("\nAES symmetric key : ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02X", (unsigned char)aes_key[i]);   //생성한 AES key 출력
    }
    printf("\n");

    char encrypted_key[BUF_SIZE] = { 0, };
    n = RSA_public_encrypt(32, aes_key, encrypted_key, rsa_pubkey, RSA_PKCS1_OAEP_PADDING); // 전달받은 공개키로 생성된 AES Key를 암호화함
    assert(n >= 0);

    n = BIO_write(socket_bio, encrypted_key, n); // AES Key를 암호화한 값 전송
    assert(n >= 0);

    sleep(1);


    RAND_bytes(iv, 16);
    printf("AES iv : ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02X", (unsigned char)iv[i]);   //생성한 AES iv 출력
    }
    printf("\n");

    char encrypted_iv[BUF_SIZE] = { 0, };

    n = RSA_public_encrypt(16, iv, encrypted_iv, rsa_pubkey, RSA_PKCS1_OAEP_PADDING); // 전달받은 공개키로 생성된 AES iv를 암호화함
    assert(n >= 0);

    n = BIO_write(socket_bio, encrypted_iv, n); // AES iv를 암호화한 값 전송
    assert(n >= 0);

    // 키 교환 완료, 통신 시작

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

    (EVP_DecryptFinal_ex(ctx, plain + out_length, &out_length));

    plain_length += out_length;
    plain[plain_length] = '\0';

    EVP_CIPHER_CTX_cleanup(ctx);
    // 복호화 수행 완료

    strcpy(buf, plain);

    return buf;
}

int login_menu()
{
    int select;

    printf("**************\n");
    printf("1. 회원가입\n");
    printf("2. 로그인\n");
    printf("3. exit\n");
    printf("**************\n");

    scanf("%d", &select);

    return select;
}
/*
    linux gcc library에 화면에 출력하지 않고 입력받는 getch 함수가 존재하지않아서
    직접 구현하였다.
    터미널의 설정을 변경하여 터미널 echo와 canonical 모드를 끄고 입력 버퍼를 1로 만든 후
    키보드 입력을 읽고 터미널 설정을 원래대로 복원하는 방식으로 구현
*/
int getch(void)
{
    int ch;
    struct termios buf;
    struct termios save;

    tcgetattr(0, &save);
    buf = save;
    buf.c_lflag &= ~(ICANON | ECHO);
    buf.c_cc[VMIN] = 1;
    buf.c_cc[VTIME] = 0;
    tcsetattr(0, TCSAFLUSH, &buf);
    ch = getchar();
    tcsetattr(0, TCSAFLUSH, &save);
    return ch;

}

//pw를 * 로 표현하는 함수
char* password(char* pw)
{
    int i = 0;
    while (i < BUF_SIZE) {        //overflow 방지

        int temp;
        temp = getch();
        if (temp == 10)break;  //enter 입력 시 break
        else if (temp == 127)
        {
            if (i > 0)
            {
                printf("\b");       //시각적으로 지움
                fputs(" ", stdout);
                printf("\b");

                pw[i - 1] = 0;        //입력된 값 지움
                i--;

            }
            continue;
        }
        else {
            pw[i] = temp;
            i++;
            printf("*");
        }
    }
    pw[i] = '\0';

    printf("\n");
    return pw;
}

//회원가입 함수
int sign_up()
{
    admin_info sign_up_admin_info;
    char admin_key[BUF_SIZE];
    char admin_id[BUF_SIZE];
    char admin_pw[BUF_SIZE];
    char admin_name[BUF_SIZE];
    int key_count = 0;

    while (1)                //admin key 입력 횟수 5회로 제한
    {
        while (getchar() != '\n');     //buffer 비우기
        printf("admin authentication screen\n");
        printf("****************************\n");
        printf("admin key : ");         //틀릴 시, 회원가입 거부
        strcpy(admin_key, password(admin_key));

        secure_write(socket_bio, admin_key, sizeof(admin_key)); //admin key 전달 
        strcpy(buf, secure_read(socket_bio, buf, BUF_SIZE));     //server 로부터 메시지 전달 받음

        printf("%s\n", buf);         //server에게 전달받은 메시지 출력

        if (!strcmp(buf, "회원가입 요청이 허용되었습니다."))
            break;
        else if (!strcmp(buf, "admin key가 틀렸습니다."))
        {
            key_count++;
            printf("시도횟수 %d회 남았습니다.\n", 5 - key_count);

            if (key_count == 5)
            {
                printf("모든 시도횟수를 사용하셨습니다.\n");
                printf("당신은 회사의 DB관리자가 아니라고 판단하여 연결을 강제 종료합니다.\n");

                sleep(2);

                BIO_free(socket_bio);
                system("clear");
                connection_status = FALSE;
                exit(1);

            }
            sleep(1);
        }
        else
        {
            fprintf(stderr, "error!\n");
            connection_status = FALSE;
            exit(-1);
        }

    }
    sleep(1);
    system("clear");

    jmp_buf env;
    setjmp(env);

    printf("sign up\n");
    printf("****************************\n");
    printf("ID : ");
    scanf("%s", admin_id);
    secure_write(socket_bio, admin_id, BUF_SIZE);

    while (getchar() != '\n');     //buffer 비우기

    printf("P.W : ");
    strcpy(admin_pw, password(admin_pw));
    secure_write(socket_bio, admin_pw, BUF_SIZE);

    printf("admin_name : ");
    scanf("%s", admin_name);
    secure_write(socket_bio, admin_name, BUF_SIZE);
    printf("****************************\n");
    strcpy(buf, secure_read(socket_bio, buf, BUF_SIZE));
    printf("%s\n", buf);

    if (!strcmp(buf, "존재하는 ID입니다."))
    {
        printf("회원가입을 다시 진행해주세요.\n");
        sleep(1);
        system("clear");
        longjmp(env, 1);
    }

    sleep(1);
    system("clear");
}

int print_menu() ///로그인 후 메뉴 선택하는 폼.
{
    int ch = 0;
    printf("******* main menu *********\n");
    printf("*******************************\n");
    printf("       [1. 사원 등록]\n");                  //Server가 client(admin)에게 부서, 사원명, 사원번호, 입사년도, 연봉(만원)을 입력받고, 부서명.csv에 사원을 정보를 저장
    printf("       [2. 부서 정보 조회]\n");             //client에게 부서명을 입력 받고, 부서명.csv의 내용을 읽어온다
    printf("       [3. 사원 정보 조회]\n");            //client에게 부서명과 사원번호, 사원명을 입력 받고, 해당 사원 정보를 출력해준다.
    printf("       [4. 사원 정보 수정]\n");            //client에게 부서명과 사원번호, 사원명을 입력 받고, 수정사항을 요청 후,수정 사항을 부서명.csv에 저장한다
    printf("       [5. 사원 정보 삭제]\n");            //client에게 부서명과 사원번호, 사원명을 입력 받고, 부서명.csv에서 사원을 제거한다.
    printf("       [6. 로그아웃]\n");
    printf("       [7. 종료]\n");
    printf("input(1~7): ");
    scanf("%d", &ch);
    return ch;
}

void client_section()
{

    while (1)
    {
        system("clear");
        int select = print_menu();

        if (select == 1)
        {

        }
        else if (select == 2)
        {

        }
        else if (select == 3)
        {

        }
        else if (select == 4)
        {

        }
        else if (select == 5)
        {

        }
        else if (select == 6)
        {

        }
        else if (select == 7)
        {

        }
        else
        {
            printf("잘못된 값을 입력하셨습니다.\n");
            printf("다시 입력해주세요.\n");
            sleep(1);
        }
    }
}

//로그인 함수
int sign_in()
{
    int login_try = 0; //5회로 제안
    char login_id[BUF_SIZE];
    char login_pw[BUF_SIZE];

    while (login_try < 5)
    {
        system("clear");

        printf("******************************\n");
        printf("          Login              \n");
        printf("******************************\n");
        printf(" ID : ");
        scanf("%s", login_id);
        while (getchar() != '\n');
        printf(" P.W : ");
        strcpy(login_pw, password(login_pw));

        secure_write(socket_bio, login_id, BUF_SIZE);
        secure_write(socket_bio, login_pw, BUF_SIZE);

        strcpy(buf, secure_read(socket_bio, buf, BUF_SIZE));

        if (!strcmp(buf, "존재하지 않는 ID이거나 PW가 틀렸습니다."))
        {
            login_try++;
            printf("%s\n", buf);
            printf("로그인 시도 횟수가 %d회 남았습니다.\n", 5 - login_try);
            sleep(1);
            continue;
        }
        else if (!strcmp(buf, "login에 성공했습니다."))
        {
            printf("%s\n", buf);
            printf("DB 관리 section에 진입합니다.\n");
            sleep(1);

            return 1;
        }
    }

    if (login_try == 5)
    {
        printf("로그인 시도 횟수를 모두 사용하셨습니다.\n");
        printf("프로그램 사용을 1분간 중단 시킵니다.\n");

        sigset_t set;

        sigaddset(&set, SIGINT);
        sigaddset(&set, SIGSTOP);
        sigprocmask(SIG_BLOCK, &set, NULL);
        sleep(10);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
        sigemptyset(&set);

        system("clear");

        return 0;                           //로그인 실패
    }


}


void Client()
{

    while (1)
    {
        int mode;

        //login_menu 호출
        mode = login_menu();

        switch (mode) {
        case 1:
        {
            secure_write(socket_bio, "sign_up", BUF_SIZE);
            sign_up();
            system("clear");
            break;
        }
        case 2: {
            secure_write(socket_bio, "sign_in", BUF_SIZE);
            if (sign_in())
            {
                client_section();               //로그인 성공 시 section 진입
            }
            break;
        }
        case 3: {
            printf("DB프로그램을 종료합니다.\n");
            secure_write(socket_bio, "exit", BUF_SIZE);
            sleep(1);
            BIO_free(socket_bio);

            system("clear");
            exit(1);
            break;
        }
        default: {
            printf("잘못된 값을 입력하셨습니다.\n");
            printf("1~3사이만 입력해주세요.\n");
            sleep(1);
            system("clear");
        }

        }
    }
}