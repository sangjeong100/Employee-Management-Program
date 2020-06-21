/*
    사원 관리 프로그램 클라이언트
    기능 : server - client 통신을 통한 사원 DB관리
    개발자 : 유상정
*/

#include "common.h"

#include <sys/signal.h>
#include <termio.h>     //getch() 함수 구현
#include <term.h>       //getch() 함수 구현


BIO* socket_bio, * out;                    //통신 socket 
int socketfd;
struct sockaddr_in server_addr, my_addr;



admin_info admin;           //admin 정보                                                                

void Client();           //Client 함수
void secure_socket_init();         //socket 연결 함수
int login_menu();          //로그인 전 메뉴
int sign_in();          //로그인
void sign_up();         //회원가입

void client_section();  //로그인 후 client section
int print_menu(); //로그인 후 메뉴 선택하는 폼.
void Employee_Registration();   //사원 등록 함수
void Department_information();  //부서 정보 조회 함수
void Employee_Search(); //사원 정보 조회 함수
void Employee_Delete(); //사원 정보 삭제 함수

int getch(void);        //입력이 출력되지 않도록 하는 함수 구현
char * password(char * pw); //pw를 "*"로 표시하는 함수

int main(int argc, char** argv)
{

    if (argc != 3)
    {
        printf("usage : ./client \"YOURIP\" \"PORT\"\n");
        exit(-1);
    }

    strcpy(HOSTADDRESS, argv[1]);
    strcat(HOSTADDRESS, ":");
    strcat(HOSTADDRESS, argv[2]);

    strcpy(HOSTIP, argv[1]);
    HOSTPORT = atoi(argv[2]) + 1;

    secure_socket_init();          //socket 연결 함수 호출
    printf("connected!\n");

    Client();


    return 0;

}

void secure_socket_init()
{
    RSA* rsa_pubkey = NULL;                //server의 RSA 공개키
    int n;

    ERR_load_crypto_strings();


    socket_bio = BIO_new_connect(HOSTADDRESS); //server와의 connection 생성(socket 생성)    -->키 교환 채널

    printf("connecting..\n");
    if (BIO_do_connect(socket_bio) <= 0)     //connection 요청
    {
        //연결 실패 오류문 호출 후 client 종료
        fprintf(stderr, "connection error!\n");
        exit(-1);
    }

    printf("Connected!\n");
    printf("read RSA public key from server...\n");

    memset(buf, 0, BUF_SIZE);

    unsigned long size;
    unsigned char c;

    if ((BIO_read(socket_bio, (unsigned char*)&size, sizeof(size))) <= 0)    //server로부터 RSA 공개키 수신
    {
        fprintf(stderr, "read error!\n");
        exit(-1);
    }
    size = ntohl(size);

    //공개키 저장을 위한 public.pem 파일 생성
    FILE* fp = fopen("public.pem", "wb");
    for (int i = 0; i <= size; i++)
    {
        //1바이트씩 수신해서 public.pem 파일에 씀 
        BIO_read(socket_bio, &c, sizeof(c));
        buf[i] = c;
        fwrite(&c, sizeof(unsigned char), 1, fp);

    }
    fclose(fp);
    fp = fopen("public.pem", "rb");             //public.pem 파일 읽음

    printf("\nRecieved Public key\n%s", buf); //공개키 출력

    rsa_pubkey = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL); //pem으로 부터 공개키를 rsa 로 읽는다.
    fclose(fp);

    RAND_bytes(aes_key, 32);        //32byte의 AES key를 랜덤 생성 (AES-256 mode)
    printf("\nAES symmetric key : ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02X", (unsigned char)aes_key[i]);   //생성한 AES key 출력
    }
    printf("\n");

    unsigned char encrypted_key[BUF_SIZE] = { 0, };
    n = RSA_public_encrypt(32, aes_key, encrypted_key, rsa_pubkey, RSA_PKCS1_OAEP_PADDING); // 전달받은 공개키로 생성된 AES Key를 암호화함
    assert(n >= 0);   //n<0 이면 프로그램 종료

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

    BIO_free(socket_bio);
    // 키 교환 완료, 통신 시작

    printf("키 교환 채널을 닫고 일반 채널을 여는중..\n");
    sleep(2); // 서버가 먼저 소켓 bind할 시간 부여

    //socket 생성
    if ((socketfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "socket error!\n");
        exit(-1);
    }

    //socket addr 구조체에 server 정보 등록
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(HOSTIP);
    server_addr.sin_port = htons(HOSTPORT);

    //connection 요청
    if ((connect(socketfd, (struct sockaddr*) & server_addr, sizeof(server_addr))) < 0) {
        printf("bind: connection refused\n");
        exit(-1);
    }
    printf("일반 통신 채널 open 완료!\n");
}

void secure_write(int socketfd, char* buffer, int buf_size)
{
    int plain_length;      //평문 길이
    int out_length = 0;        //CipherUpdate, CipherFinal 함수에서 out data 길이를 저장
    int cipher_length;       //암호문 길이

    char cipher[BUF_SIZE] = { 0, };   //암호문

    EVP_CIPHER_CTX* ctx;                //암호화 컨텍스트 -> 암호화 데이터의 정보 저장되는 구조체

    if (!(ctx = EVP_CIPHER_CTX_new())) //암호화 context 초기화
    {
        fprintf(stderr, "ctx new error!\n");
        exit(-1);
    }

    plain_length = 1024;

    //AES 256 cbc 모드로 암호화 진행
    //암호화를 위한 초기 설정
    if ((EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) != 1)
    {
        fprintf(stderr, "EVP_EncryptInit error!\n");
        exit(-1);
    }
    //암호화 수행
    if ((EVP_EncryptUpdate(ctx, cipher, &out_length, buffer, plain_length)) != 1)
    {
        fprintf(stderr, "EVP_CipherUpdate error!\n");
        exit(-1);
    }

    cipher_length = out_length;
    //패딩등 필요한 작업을 처리
    if ((EVP_EncryptFinal_ex(ctx, cipher + out_length, &out_length)) != 1)
    {
        fprintf(stderr, "EV_EnctyptFinal error!\n");
        exit(-1);
    }
    cipher_length += out_length;
    cipher[cipher_length] = '\0';

    for (int i = cipher_length + 1; i < BUF_SIZE; i++)
        cipher[i] = 0;

    EVP_CIPHER_CTX_cleanup(ctx);
    //암호화 완료

    if ((write(socketfd, cipher, BUF_SIZE)) <= 0)    //암호화된 data 전송
    {
        fprintf(stderr, "write error!\n");

        exit(-1);
    }

}

char* secure_read(int socketfd, char* buffer, int buf_size)
{
    int cipher_length = 0; // 수신한 암호문의 길이
    int out_length = 0; // CipherUpdate, CipherFinal 함수에서 out 데이터 길이를 저장할 변수
    int plain_length = 0; // 평문 길이

    char plain[BUF_SIZE] = { 0, }; // 복호화한 데이터

    EVP_CIPHER_CTX* ctx; // EVP context 변수

    if (!(ctx = EVP_CIPHER_CTX_new()))//ctx 초기화
    {
        fprintf(stderr, "ctx new error!\n");
        exit(-1);
    }

    memset(buffer, 0, BUF_SIZE);        //buf 배열 초기화
    for (int i = 0; i < BUF_SIZE; i++)
    {
        char temp;
        if ((read(socketfd, &temp, 1)) <= 0)  //암호화된 data 수신               
        {
            fprintf(stderr, "read error!\n");
            exit(-1);
        }
        buffer[i] = temp;
    }
    cipher_length = 1040;

    //AES-256 cbc 모드로 복호화 수행
     //복호화 전, 초기 설정
    if ((EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) != 1)
    {
        fprintf(stderr, "EVP_DecryptInit error!\n");
        exit(-1);
    }
    //복호화 수행
    if ((EVP_DecryptUpdate(ctx, plain, &out_length, buffer, cipher_length)) != 1)
    {
        fprintf(stderr, "EVP_DecryptUpdate error!\n");
        exit(-1);
    }
    plain_length = out_length;

    //패딩을 없애는 등, 필요한 작업 처리
    (EVP_DecryptFinal_ex(ctx, plain + out_length, &out_length));

    plain_length += out_length;
    plain[plain_length] = '\0';

    EVP_CIPHER_CTX_cleanup(ctx);
    //    복호화 수행 완료
    for (int i = plain_length + 1; i < BUF_SIZE; i++)
        plain[i] = 0;

    strcpy(buffer, plain);

    return buffer;
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
    struct termios buff;
    struct termios save;

   tcgetattr(0, &save);             //원래의 터미널 설정 save
   buff = save;                     
   buff.c_lflag &= ~(ICANON|ECHO);  //터미널 echo와 canonical 모드를 끔
   buff.c_cc[VMIN] = 1;             //입력 buffer를 1으로 만듬
   buff.c_cc[VTIME] = 0;            //출력 buffer를 0으로 만듬
   tcsetattr(0, TCSAFLUSH, &buff);  //현재 터미널 모드를 바꿈
   ch = getchar();                  //키보드로 부터 한글자 입력을 받음
   tcsetattr(0, TCSAFLUSH, &save);  //입력받은 후 터미널 설정을 원래대록 복원
   return ch;                       //입력된 값을 return

}

//pw를 * 로 표현하는 함수
char* password(char* pw)
{
    __fpurge(stdin);     //buffer 비우기
    int i = 0;
    while (i < BUF_SIZE) {        //overflow 방지

        int temp;
        temp = getch();         //입력된 값 print되는 것 막는 함수
        if (temp == 10) break;  //enter 입력 시 break
        else if (temp == 127)
        {
            if (i > 0)
            {
                printf("\b");       //backspace를 print하여 
                fputs(" ", stdout); //시각적으로  *을 지운다.
                printf("\b");

                pw[i - 1] = 0;        //실제로 입력된값을 지운다.
                i--;                  //입력될 위치 조정

            }
            continue;
        }
        else {
            pw[i] = temp;
            i++;
            printf("*");
        }
    }
    pw[i] = '\0';           //문자열로 만들기 위해 null값 삽입

    printf("\n");

    return pw;
}

//회원가입 함수
void sign_up()
{
    int key_count = 0;
    admin_info sign_up_admin_info;
    char admin_id[BUF_SIZE];
    char admin_pw[BUF_SIZE];
    char admin_name[BUF_SIZE];


    while (1)                //admin key 입력 횟수 5회로 제한
    {
        char admin_key[BUF_SIZE] = { 0, };

        printf("admin authentication screen\n");
        printf("****************************\n");
        printf("admin key : ");         //틀릴 시, 회원가입 거부
        strcpy(admin_key, password(admin_key));

        secure_write(socketfd, admin_key, sizeof(admin_key)); //admin key 전달 
        strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));     //server 로부터 메시지 전달 받음

        printf("%s\n", buf);         //server에게 전달받은 메시지 출력

        if (!strcmp(buf, "회원가입 요청이 허용되었습니다."))
        {
            memset(buf, 0, BUF_SIZE);
            break;
        }
        else if (!strcmp(buf, "admin key가 틀렸습니다."))
        {
            key_count++;
            printf("시도횟수 %d회 남았습니다.\n", 5 - key_count);
            memset(admin_key, 0, BUF_SIZE);

            if (key_count == 5)
            {
                printf("모든 시도횟수를 사용하셨습니다.\n");
                printf("당신은 회사의 DB관리자가 아니라고 판단하여 연결을 강제 종료합니다.\n");

                memset(buf, 0, BUF_SIZE);

                sleep(2);

                BIO_free(socket_bio);
                system("clear");
                exit(1);

            }
            sleep(1);
        }
        else
        {
            fprintf(stderr, "error!\n");
            exit(-1);
        }

    }
    sleep(1);
    system("clear");

    memset(buf, 0, BUF_SIZE);

    printf("sign up\n");
    printf("****************************\n");
    printf("ID : ");
    scanf("%s", admin_id);
    secure_write(socketfd, admin_id, BUF_SIZE);

    printf("P.W : ");
    strcpy(admin_pw, password(admin_pw));
    secure_write(socketfd, admin_pw, BUF_SIZE);

    printf("admin_name : ");
    scanf("%s", admin_name);
    secure_write(socketfd, admin_name, BUF_SIZE);
    printf("****************************\n");
    strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));
    printf("%s\n", buf);

    if (!strcmp(buf, "존재하는 ID입니다."))
    {
        printf("회원가입을 다시 진행해주세요.\n");
    }
    memset(buf, 0, BUF_SIZE);
    sleep(2);
    system("clear");
}

int print_menu() ///로그인 후 메뉴 선택하는 폼.
{
    int ch;
    printf("********* main menu ***********\n");
    printf("*******************************\n");
    printf("       [1. 사원 등록]\n");                  //Server가 client(admin)에게 부서, 사원명, 사원번호, 입사년도, 연봉(만원)을 입력받고, 부서명.csv에 사원을 정보를 저장
    printf("       [2. 부서 정보 조회]\n");             //client에게 부서명을 입력 받고, 부서명.csv의 내용을 읽어온다
    printf("       [3. 사원 정보 조회]\n");            //client에게 부서명과 사원번호, 사원명을 입력 받고, 해당 사원 정보를 출력해준다.
    printf("       [4. 사원 정보 삭제]\n");            //client에게 부서명과 사원번호, 사원명을 입력 받고, 부서명.csv에서 사원을 제거한다.
    printf("       [5. 로그아웃]\n");
    printf("       [6. 종료]\n");
    printf("input(1~6): ");
    scanf("%d", &ch);

    return ch;
}

/*
    Employee Registration 루틴
*/
void Employee_Registration()
{
    char department[BUF_SIZE];
    char employee_name[BUF_SIZE];
    char employee_number[BUF_SIZE];
    char join_year[BUF_SIZE];
    char annual_salary[BUF_SIZE];

    while (1)
    {
        system("clear");
        printf("************ 사원 등록  **************\n");
        printf("**************************************\n");
        printf("**************부서 목록***************\n");
        printf("*** 경영팀, 인사팀, 개발팀, 홍보팀 ***\n");
        printf("**************************************\n");
        printf("존재하는 부서 외에 입력할 수 없습니다.\n");

        printf("사원의 부서 : "); scanf("%s", department);

        if (!strcmp(department, "경영팀") || !strcmp(department, "인사팀") || !strcmp(department, "개발팀") || !strcmp(department, "홍보팀"))  //등록된 부서만 업력할 것
        {
            break;
        }
        else {
            printf("등록되지 않은 부서입니다.\n");
            printf("다시 입력해 주세요.\n");
            sleep(1);
        }
    }
    secure_write(socketfd, department, BUF_SIZE);


    printf("employee_name : "); scanf("%s", employee_name);
    secure_write(socketfd, employee_name, BUF_SIZE);

    printf("employee_number : "); scanf("%s", employee_number);
    secure_write(socketfd, employee_number, BUF_SIZE);

    printf("join_year : "); scanf("%s", join_year);
    secure_write(socketfd, join_year, BUF_SIZE);

    printf("annual_salary : "); scanf("%s", annual_salary);
    secure_write(socketfd, annual_salary, BUF_SIZE);

    memset(buf, 0, BUF_SIZE);
    strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));
    fprintf(stderr, "%s\n", buf);

    sleep(2);

    memset(buf, 0, BUF_SIZE);

    return;

}

/*
    부서 사원 정보 출력
*/
void Department_information()
{
    char department[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);

    while (1)
    {
        system("clear");

        printf("***************************************\n");
        printf("**************부서 목록***************\n");
        printf("*** 경영팀, 인사팀, 개발팀, 홍보팀 ****\n");
        printf("****************************************\n");
        printf("존재하는 부서 외에 입력할 수 없습니다.\n");
        printf("******조회할 부서를 입력해주세요.******\n");
        printf("조회할 부서 : "); scanf("%s", department);

        if (!strcmp(department, "경영팀") || !strcmp(department, "인사팀") || !strcmp(department, "개발팀") || !strcmp(department, "홍보팀"))  //등록된 부서만 업력할 것
        {
            break;
        }
        else
        {
            printf("등록되지 않은 부서입니다.\n");
            printf("다시 입력해 주세요.\n");
            sleep(1);
        }
    }

    secure_write(socketfd, department, BUF_SIZE);
    printf("*******************************************************\n");
    printf("부서명     사원이름     사원번호     입사년도     연봉\n");
    printf("*******************************************************\n");

    while (1)
    {
        memset(buf, 0, BUF_SIZE);
        strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));

        if (!strcmp(buf, "파일 끝 도달"))
        {
            memset(buf, 0, BUF_SIZE);
            break;
        }
        else
        {
            char tem[5][BUF_SIZE] = { 0, };
            char* p = strtok(buf, " \n");
            int cnt = 0;
            while (p != NULL)
            {
                strcpy(tem[cnt], p);
                if (cnt == 4)
                    printf("%s", tem[cnt]);
                else
                    printf("%s     ", tem[cnt]);
                cnt++;

                p = strtok(NULL, " \n");

            }
            printf("\n");
        }
    }
    printf("***************************************************\n");
    printf("부서 정보 조회를 마칩니다.\n");
    printf("이전 메뉴로 돌아가고자 한다면, 아무거나 입력해주세요.\n");

    char input[BUF_SIZE];
    scanf("%s", input);
    memset(buf, 0, BUF_SIZE);


    return;

}
/*
    사원 검색 후 출력
*/
void Employee_Search()
{
    while (1)
    {
        memset(buf, 0, BUF_SIZE);
        system("clear");
        int select;
        printf("***************** 사원 정보 조회 *******************\n");
        printf("****************************************************\n");
        printf("****** 검색 옵션 ***********************************\n");
        printf("       [1. 사원 이름으로 검색]\n");
        printf("       [2. 사원 번호로 검색]\n");
        printf("       [3. 연봉으로 검색]\n");
        printf("       [4. 입사년도로 검색]\n");
        printf("Input(1~4) : ");
        scanf("%d", &select);

        if (select == 1)
        {
            secure_write(socketfd, "employee name", BUF_SIZE);

            char employee_name[BUF_SIZE] = { 0, };
            printf("검색할 사원 이름 : "); scanf("%s", employee_name);
            secure_write(socketfd, employee_name, BUF_SIZE);
            sleep(1);
            break;

        }
        else if (select == 2)
        {
            secure_write(socketfd, "employee number", BUF_SIZE);

            char employee_number[BUF_SIZE] = { 0, };
            printf("검색할 사원 번호 : "); scanf("%s", employee_number);
            secure_write(socketfd, employee_number, BUF_SIZE);
            sleep(1);
            break;
        }
        else if (select == 3)
        {
            secure_write(socketfd, "annual salary", BUF_SIZE);

            char annual_salary[BUF_SIZE] = { 0, };
            printf("검색할 연봉 : "); scanf("%s", annual_salary);
            secure_write(socketfd, annual_salary, BUF_SIZE);
            sleep(1);
            break;
        }
        else if (select == 4)
        {
            secure_write(socketfd, "join year", BUF_SIZE);

            char join_year[BUF_SIZE] = { 0, };
            printf("검색할 입사년도 : "); scanf("%s", join_year);
            secure_write(socketfd, join_year, BUF_SIZE);
            sleep(1);
            break;
        }
        else
        {
            printf("잘못된 값을 입력하였습니다.\n");
            printf("다시 선택해주세요.\n");
            sleep(1);
        }
    }
    system("clear");
    printf("*******************************************************\n");
    printf("부서명     사원이름     사원번호     입사년도     연봉\n");
    printf("*******************************************************\n");

    while (1)
    {
        memset(buf, 0, BUF_SIZE);
        strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));


        if (!strcmp(buf, "파일 끝 도달"))
        {
            memset(buf, 0, BUF_SIZE);
            break;
        }
        else
        {
            char tem[5][BUF_SIZE] = { 0, };
            char* p = strtok(buf, " \n");
            int cnt = 0;
            while (p != NULL)
            {
                strcpy(tem[cnt], p);
                printf("%s     ", tem[cnt]);
                cnt++;

                p = strtok(NULL, " \n");

            }
            printf("\n");
        }
    }
    printf("***************************************************\n");
    printf("사원 정보 조회를 마칩니다.\n");
    printf("이전 메뉴로 돌아가고자 한다면, 아무거나 입력해주세요.\n");

    char input[BUF_SIZE];
    scanf("%s", input);
    memset(buf, 0, BUF_SIZE);

    return;
}
/*
    사원정보 삭제 구간
    사원번호를 입력받아서 삭제한다.
*/
void Employee_Delete()
{
    memset(buf, 0, BUF_SIZE);
    system("clear");

    printf("***************** 사원 정보 삭제 *******************\n");
    printf("****************************************************\n");
    printf("삭제할 사원의 번호 : "); scanf("%s", buf);

    secure_write(socketfd, buf, BUF_SIZE);           //삭제할 사원의 번호 전달
    sleep(1);
    memset(buf, 0, BUF_SIZE);
    secure_read(socketfd, buf, BUF_SIZE);

    printf("%s\n", buf);
    sleep(1);

    return;
}

/*
    로그인성공 후 client Section
*/
void client_section()
{
    while (1)
    {
        system("clear");

        int select = print_menu();

        if (select == 1)
        {
            secure_write(socketfd, "employee registration", BUF_SIZE);

            sleep(1);
            Employee_Registration();                                    //사원등록 구간
        }
        else if (select == 2)
        {
            secure_write(socketfd, "Department Information", BUF_SIZE);

            sleep(1);
            Department_information();                                   //부서 사원 정보 출력 구간
        }
        else if (select == 3)
        {
            secure_write(socketfd, "Employee Search", BUF_SIZE);

            sleep(1);
            Employee_Search();                                     //사원 정보 검색

        }
        else if (select == 4)
        {
            secure_write(socketfd, "Employee Delete", BUF_SIZE);

            sleep(1);
            Employee_Delete();                                  //사원 정보 삭제
        }
        else if (select == 5)
        {
            secure_write(socketfd, "log out", BUF_SIZE);
            strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));

            memset(buf, 0, BUF_SIZE);

            printf("DB Section을 종료하고 로그아웃합니다.\n");
            break;
        }
        else if (select == 6)
        {
            secure_write(socketfd, "exit", BUF_SIZE);
            strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));

            memset(buf, 0, BUF_SIZE);

            printf("DB프로그램을 종료합니다.\n");

            sleep(1);
            close(socketfd);

            system("clear");
            exit(1);
        }
        else
        {
            printf("잘못된 값을 입력하셨습니다.\n");
            printf("다시 입력해주세요.\n");
            sleep(1.5);
        }
    }
}

//로그인 함수
int sign_in()
{
    int login_try = 0; //5회로 제안
    char login_id[BUF_SIZE] = { 0, };
    char login_pw[BUF_SIZE] = { 0, };

    while (login_try < 5)
    {
        system("clear");

        printf("******************************\n");
        printf("          Login              \n");
        printf("******************************\n");
        printf(" ID : ");
        scanf("%s", login_id);
        printf(" P.W : ");
        while (getchar() != '\n');
        strcpy(login_pw, password(login_pw));

        secure_write(socketfd, login_id, BUF_SIZE);
        sleep(1);
        secure_write(socketfd, login_pw, BUF_SIZE);
        sleep(1);

        memset(buf, 0, BUF_SIZE);
        strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));

        if (!strcmp(buf, "등록된 ID가 존재하지 않습니다."))
        {
            printf("%s\n", buf);
            memset(buf, 0, BUF_SIZE);
            sleep(1);
            return FALSE;
        }

        else if (!strcmp(buf, "존재하지 않는 ID이거나 PW가 틀렸습니다."))
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

            memset(buf, 0, BUF_SIZE);

            printf("DB 관리 section에 진입합니다.\n");
            sleep(1);

            return TRUE;
        }
        else {
            printf("%s\n", buf);
            sleep(2);
            return TRUE;
        }
    }

    if (login_try == 5)
    {
        memset(buf, 0, BUF_SIZE);
        printf("로그인 시도 횟수를 모두 사용하셨습니다.\n");
        printf("프로그램 사용을 1분간 중단 시킵니다.\n");

        sleep(60);

        system("clear");

        return 0;                           //로그인 실패
    }


}


void Client()
{
    sleep(1);
    while (1)
    {
        int mode;

        //login_menu 호출
        mode = login_menu();

        switch (mode) {
        case 1:
        {
            secure_write(socketfd, "sign_up", BUF_SIZE);
            sleep(1);
            sign_up();
            system("clear");
            break;
        }
        case 2: {
            secure_write(socketfd, "sign_in", BUF_SIZE);
            sleep(1);
            if (sign_in())
            {
                client_section();               //로그인 성공 시 section 진입
                system("clear");
            }
            break;
        }
        case 3: {
            secure_write(socketfd, "exit", BUF_SIZE);
            sleep(1);

            strcpy(buf, secure_read(socketfd, buf, BUF_SIZE));
            if (!strcmp(buf, "error발생"))
            {
                printf("error발생!\n");
                printf("다시 시도 해주세요.\n");
                memset(buf, 0, BUF_SIZE);
                continue;
            }
            memset(buf, 0, BUF_SIZE);
            printf("DB프로그램을 종료합니다.\n");
            sleep(1);
            close(socketfd);


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