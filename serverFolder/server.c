/*
    사원 관리 프로그램 서버
    기능 : server - client 통신을 통한 사원 DB관리
    개발자 : 유상정
*/

#include "common.h"


#define ADMIN_LIST "./admin_data.csv" // 회원가입했을 때 기록되는 admin LIST파일
#define EMPLOYEE_LIST "./employee_data.txt" //전체 사원 LIST

#define ADMIN_KEY "1011"              //ADMIN_KEY


BIO *server_bio, *client_bio, *out;                 //socket 통신
RSA *rsa_object = NULL;                 //rsa 암호 object
RSA *rsa_pub = NULL;
int server_socketfd, socketfd;
struct sockaddr_in client_addr, server_addr;


admin_info admin;                       //로그인 중인 admin 저장.

void secure_socket_init();                     //socket bind 함수
void connect_listen();                  //socket listen 함수

void Server();                          //server routine 시작
int sign_in();                          //로그인 처리
int sign_up();                          //회원가입 처리

int server_section();               //로그인 후 server section
void Employee_Registration();       //사원 등록 처리
void Department_Information();      //부서 정보 조회 처리
void Employee_Search();             //사원 정보 조회 처리
void Employee_Delete();             //사원 정보 삭제 처리

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        printf("usage : ./server \"YOURIP\" \"PORT\"\n");
        exit(-1);
    }

    strcpy(HOSTADDRESS,argv[1]);
    strcat(HOSTADDRESS,":");
    strcat(HOSTADDRESS,argv[2]);
    
    strcpy(HOSTIP,argv[1]);
    HOSTPORT = atoi(argv[2])+1;

    printf("server의 종료를 원하면 Ctrl + C 를 눌러주세요.\n");

    secure_socket_init();                      //secure socket 연결 함수 호출 
    connect_listen();     //socket listen 함수
            
    Server();           //server routine
    
    return 0;
}
void secure_write(int socketfd, char * buffer, int buf_size)
{
    int plain_length;      //평문 길이
    int out_length = 0;        //CipherUpdate, CipherFinal 함수에서 out data 길이를 저장
    int cipher_length;       //암호문 길이

    char cipher[BUF_SIZE] = {0,};   //암호문

    EVP_CIPHER_CTX *ctx;                //암호화 컨텍스트 -> 암호화 데이터의 정보 저장되는 구조체

    if(!(ctx = EVP_CIPHER_CTX_new()))  //ctx 초기화
    {
        fprintf(stderr,"ctx new error!\n");
        exit(-1);
    }

    plain_length = 1024;

    //AES 256 cbc 모드로 암호화 진행
    //암호화를 위한 초기 설정
    if((EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(), NULL, aes_key, iv)) != 1)
    {
        fprintf(stderr, "EVP_EncryptInit error!\n");
        exit(-1);
    }

    //암호화 수행
    if((EVP_EncryptUpdate(ctx, cipher, &out_length, buffer, plain_length)) != 1)
    {
        fprintf(stderr, "EVP_CipherUpdate error!\n");
        exit(-1);
    }

    cipher_length = out_length;

    //패딩등 필요한 작업을 처리
    if ((EVP_EncryptFinal_ex(ctx, cipher + out_length, &out_length)) != 1)
    {
        fprintf(stderr,"EV_EnctyptFinal error!\n");
        exit(-1);
    }
    cipher_length += out_length;
    cipher[cipher_length] = '\0';

    for(int i = cipher_length +1;i<BUF_SIZE;i++)
        cipher[i] = 0;


    EVP_CIPHER_CTX_cleanup(ctx);
    //암호화 완료

    if((write(socketfd,cipher,BUF_SIZE)) <= 0 )    //암호화된 data 전송
    {
        fprintf(stderr,"write error!\n");

        exit(-1);
    }

}

char * secure_read(int socketfd,char * buffer,int buf_size)
{
    int cipher_length = 0; // 수신한 암호문의 길이
    int out_length = 0; // CipherUpdate, CipherFinal 함수에서 out 데이터 길이를 저장할 변수
    int plain_length = 0; // 평문 길이

    char plain[BUF_SIZE] = {0,}; // 복호화한 데이터
    
    EVP_CIPHER_CTX *ctx; // EVP context 변수

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        fprintf(stderr,"ctx new error!\n");
        exit(-1);
    }

    memset(buffer, 0, BUF_SIZE);        //buf 배열 초기화
    for(int i =0;i<BUF_SIZE;i++)
    {
        char temp;
        if((read(socketfd,&temp,1)) <= 0)  //암호화된 data 수신               
        {
            fprintf(stderr,"read error!\n");
            exit(-1);
        }
        buffer[i] = temp;
    }
    cipher_length = 1040;

    //AES-128 cbc 모드로 복호화 수행
    if ((EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) != 1)
    {
        fprintf(stderr,"EVP_DecryptInit error!\n");
        exit(-1);
    }
    if ((EVP_DecryptUpdate(ctx, plain, &out_length, buffer, cipher_length)) != 1)
    {
        fprintf(stderr,"EVP_DecryptUpdate error!\n");
        exit(-1);
    }
    plain_length = out_length;
    
    EVP_DecryptFinal_ex(ctx, plain + out_length, &out_length);

    plain_length += out_length;
    plain[plain_length] = '\0';
    
    EVP_CIPHER_CTX_cleanup(ctx);
    // 복호화 수행 완료

    for(int i = plain_length+1;i<BUF_SIZE;i++)
        plain[i] = 0;

    strcpy(buffer,plain);

    return buffer;
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
    while(key_count<5)
    {
        strcpy(admin_key,secure_read(socketfd,admin_key,BUF_SIZE));              //admin_key 입력 read
        
        if(!strcmp(ADMIN_KEY,admin_key))                                                //옳은 admin_key인지 확인
        {
            printf("Client에게 회원가입 자격을 부여합니다.\n");
            secure_write(socketfd,"회원가입 요청이 허용되었습니다.",BUF_SIZE);
                                                               //id 존재시, 돌아올 지점 setjmp

            //회원가입 id, pw, name 받음
            strcpy(sign_up_admin.id,secure_read(socketfd,sign_up_admin.id,BUF_SIZE));    
            strcpy(sign_up_admin.pw,secure_read(socketfd,sign_up_admin.pw,BUF_SIZE));
            strcpy(sign_up_admin.name,secure_read(socketfd,sign_up_admin.name,BUF_SIZE));
            
            /*
                admin 파일에 회원가입된 admin 저장 
            */
            int isExist = 0;
            FILE *admin_fp; 
            if((admin_fp = fopen(ADMIN_LIST,"a+b")) == NULL)
            {
                fprintf(stderr,"fopen error\n");
                exit(-1);
            }

            char tmp[3][BUF_SIZE];
            
            char str_tmp[BUF_SIZE];
            char *p;

            //같은 id가 있는지 검사
            while(!feof(admin_fp))
            { 
                fgets(str_tmp,BUF_SIZE,admin_fp); 
            
                p = strtok(str_tmp,", \n");
                int cnt = 0;

                while(p != NULL)
                {
                    strcpy(tmp[cnt],p);
                    cnt++;
                    p=strtok(NULL, ", \n");
                }
                if(!strcmp(tmp[0],sign_up_admin.id))
                { 
                    isExist = 1;
                    fclose(admin_fp);
                    break;
                }
            }


            if(isExist)                                                     //id 존재하면
            {
                secure_write(socketfd,"존재하는 ID입니다.",BUF_SIZE);
                printf("Client가 존재하는 ID를 입력하여 회원가입을 거부합니다.\n");
                fclose(admin_fp);
                break;
            }
            else
            {
                fprintf(admin_fp,"%s, %s, %s\n",sign_up_admin.id,sign_up_admin.pw,sign_up_admin.name);

                printf("전달받은 admin 정보를 등록합니다.\n");
                printf("********************\n");
                printf("admin_id : %s\n",sign_up_admin.id);
                printf("admin_name : %s\n",sign_up_admin.name);
                printf("********************\n");

                secure_write(socketfd,"Admin가입에 성공하셨습니다.",BUF_SIZE);
                fclose(admin_fp);
                break;
            }
        }
        else
        {
            printf("Client가 admin key를 틀렸습니다.\n");
            secure_write(socketfd,"admin key가 틀렸습니다.",BUF_SIZE);
            key_count++;
        }
        
    }
    

    if (key_count == 5)      //client가 admin key 5회 틀렸을 시, client는 강제종료 되어서 
    {
        printf("Client가 admin_key 입력기회를 모두 사용하였습니다.\n");
        return 0;
    }
    else 
        return 1;
}

int sign_in()
{
    
    admin_info sign_in_admin = {0,};
    int login_try = 0;
    
    while(login_try <5)
    {

        sleep(1);
        strcpy(sign_in_admin.id,secure_read(socketfd,sign_in_admin.id,BUF_SIZE));
        sleep(1);
        strcpy(sign_in_admin.pw,secure_read(socketfd,sign_in_admin.pw,BUF_SIZE));

        printf("입력받은 ID : %s\n",sign_in_admin.id);

        FILE *admin_fp; 
        if((admin_fp = fopen(ADMIN_LIST,"rb")) == NULL)
        {
            fprintf(stderr,"등록된 ID가 존재하지 않습니다.\n");
            secure_write(socketfd,"등록된 ID가 존재하지 않습니다.",BUF_SIZE);
            return FALSE;
        }

        
        char tmp[3][BUF_SIZE];
        char str_tmp[BUF_SIZE];
        char *p;
        int isExist = 0;

        //같은 id가 있는지 검사
        while(!feof(admin_fp))
        { 
            fgets(str_tmp,BUF_SIZE,admin_fp); 
        
            p = strtok(str_tmp,", \n");
            int cnt = 0;

            while(p != NULL)
            {
                strcpy(tmp[cnt],p);
                cnt++;
                p=strtok(NULL, ", \n");
            }
            if(!strcmp(tmp[0],sign_in_admin.id))
            { 
                isExist = 1;
                fclose(admin_fp);
                break;
            }
        }
        if(isExist)
        {
            if(!strcmp(tmp[1],sign_in_admin.pw))
            {
                printf("Client가 login에 성공하였습니다.\n");
                memset(buf, 0 , BUF_SIZE);
                strcpy(buf,"login에 성공했습니다.");

                secure_write(socketfd,buf,BUF_SIZE);
                
                admin = sign_in_admin;                  //로그인 성공한 admin 정보 저장

                strcpy(admin.name,tmp[2]);              //이름도 저장

                return 1;
            }
            else                //비밀번호 잘못 입력
            {
                login_try++;
                printf("Client가 잘못된 PW를 입력하였습니다.\n");
                memset(buf, 0 , BUF_SIZE);
                strcpy(buf,"존재하지 않는 ID이거나 PW가 틀렸습니다.");
                secure_write(socketfd,buf,BUF_SIZE);
                continue;
            }
            
        }
        else            //id 잘못 입력
        {
            login_try++;
            printf("Client가 존재하지 않는 ID를 입력하였습니다.\n");
            secure_write(socketfd,"존재하지 않는 ID이거나 PW가 틀렸습니다.",BUF_SIZE);
            continue;
        }
        

    }

    return 0;

}

/*
    사원등록 Routine
*/
void Employee_Registration()
{
    char department[BUF_SIZE];
    char employee_name[BUF_SIZE];
    char employee_number[BUF_SIZE];
    char join_year[BUF_SIZE];
    char annual_salary[BUF_SIZE];

    memset(buf, 0 , BUF_SIZE);
    strcpy(department,secure_read(socketfd,buf,BUF_SIZE));    //사원 부서 받음
    memset(buf, 0 , BUF_SIZE);
    strcpy(employee_name,secure_read(socketfd,buf,BUF_SIZE));    //사원 이름 받음
    memset(buf, 0 , BUF_SIZE);
    strcpy(employee_number,secure_read(socketfd,buf,BUF_SIZE));    //사원 번호 받음
    memset(buf, 0 , BUF_SIZE);
    strcpy(join_year,secure_read(socketfd,buf,BUF_SIZE));         //입사년도 받음
    memset(buf, 0 , BUF_SIZE);
    strcpy(annual_salary,secure_read(socketfd,buf,BUF_SIZE));    //연봉 받음
    memset(buf, 0 , BUF_SIZE);

    printf("*********받은 사원 정보 ************\n");
    printf("부서 : %s\n",department);
    printf("사원 이름 : %s\n",employee_name);
    printf("사원 번호 : %s\n",employee_number);
    printf("입사년도 : %s\n",join_year);
    printf("연봉 : %s\n",annual_salary);
    

    FILE *employee_fp; 
        if((employee_fp = fopen(EMPLOYEE_LIST,"a+t")) == NULL)
        {
            fprintf(stderr,"fopen error\n");
            exit(-1);
        }

        
        char tmp[5][BUF_SIZE];
        char str_tmp[BUF_SIZE];
        char *p;
        int isExist = 0;

        //같은 사원번호가 있는지 검사
        while(!feof(employee_fp))
        { 
            fgets(str_tmp,BUF_SIZE,employee_fp); 
            fscanf(employee_fp, "%s %s %s %s %s",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4]);
        
            if(!strcmp(tmp[2],employee_number))
            { 
                isExist = 1;
                fclose(employee_fp);
                break;
            }
        }
        if(isExist)                                             //사원 번호는 고유하므로, 사원 번호로 구분한다.
        {
            secure_write(socketfd,"이미 존재하는 사원입니다.",BUF_SIZE);
            sleep(2);
            printf("Client가 이미 존재하는 사원을 입력하였습니다\n");
            return;
        }
        else
        {
            fprintf(employee_fp,"%s %s %s %s %s\n",department,employee_name, employee_number, join_year, annual_salary);
            fclose(employee_fp);

            FILE * department_fp;
            
            char department_file[BUF_SIZE];
            strcpy(department_file,department);
            strncat(department_file,".txt",4);                          //부서명.csv로 만듬

            if((department_fp = fopen(department_file,"a+t")) == NULL)              //부서파일 open
            {
                fprintf(stderr,"fopen error\n");
                exit(-1);
            }

            fprintf(department_fp,"%s %s %s %s %s\n",department,employee_name, employee_number, join_year, annual_salary);
            fclose(department_fp);
            
            secure_write(socketfd,"사원등록처리가 되었습니다.",BUF_SIZE);
            sleep(2);

           printf("사원 등록 처리를 끝마칩니다.\n");
            return;

        }
        

}

/*
    부서정보검색
*/
void Department_Information()
{
    char department[BUF_SIZE];
    memset(buf,0,BUF_SIZE);
    strcpy(department,secure_read(socketfd,buf,BUF_SIZE));    //부서를 입력받음
    memset(buf,0,BUF_SIZE);
    printf("요청받은 부서 : %s\n",department);

    char department_file[BUF_SIZE];
    
    strcpy(department_file,department);
    strncat(department_file,".txt",4);                          //부서명.txt로 만듬
   
    FILE * department_fp;
    if((department_fp = fopen(department_file,"a+t")) == NULL)              //부서파일 open
    {
        fprintf(stderr,"fopen error\n");
        exit(-1);
    }
    char temp_str[BUF_SIZE] = {0,};

    while(!feof(department_fp))
    { 
        memset(temp_str,0,BUF_SIZE);
        fgets(temp_str,BUF_SIZE,department_fp);                  //파일 한줄 읽고
        printf("%s",temp_str);
        secure_write(socketfd,temp_str,BUF_SIZE);              //client에게 전송
    }

    secure_write(socketfd,"파일 끝 도달",BUF_SIZE);

    fclose(department_fp);
    printf("부서 정보 조회를 끝마칩니다.\n");

    return;

}

/*
    사원 검색 구간
*/
void Employee_Search()
{
    int check;
    char select[BUF_SIZE];
    while(1)
    {
        memset(select,0,BUF_SIZE);
        strcpy(select,secure_read(socketfd,select,BUF_SIZE)); //client로 부터 mode 읽어옴
        sleep(1);
        
        if(!strcmp(select,"employee name"))
        {
            printf("admin이 사원 이름으로 검색을 요청했습니다.\n");

            memset(buf, 0 ,BUF_SIZE);
            strcpy(buf,secure_read(socketfd,buf,BUF_SIZE));
            printf("검색을 요청받은 employee_name : %s\n",buf);
            check = 1;
            
            break;
        }
        else if (!strcmp(select,"employee number"))
        {   
            printf("admin이 사원 번호로 검색을 요청했습니다.\n");
            
            memset(buf, 0 ,BUF_SIZE);
            strcpy(buf,secure_read(socketfd,buf,BUF_SIZE));
            printf("검색을 요청받은 employee number : %s\n",buf);
            check = 2;
            
            break;
        }
        else if (!strcmp(select,"annual salary"))
        {
            printf("admin이 연봉으로 검색를 요청했습니다.\n");
            
            memset(buf, 0 ,BUF_SIZE);
            strcpy(buf,secure_read(socketfd,buf,BUF_SIZE));            
            printf("검색을 요청받은 annual salary : %s\n",buf);
            check = 3;            
            
            break;
        }
        else if(!strcmp(select,"join year"))
        {
            printf("admin이 입사년도로 검색를 요청했습니다.\n");
            
            memset(buf, 0 ,BUF_SIZE);
            strcpy(buf,secure_read(socketfd,buf,BUF_SIZE));
            printf("검색을 요청받은 join year : %s\n",buf);
            check = 4;            
            
            break;
        }   
    }
    
    FILE *employee_fp; 
    if((employee_fp = fopen(EMPLOYEE_LIST,"a+t")) == NULL)        //Userlist 파일 open
    {
        fprintf(stderr,"fopen error\n");
        exit(-1);
    }
   

    char send_tmp[BUF_SIZE];
    char str_tmp[BUF_SIZE];
    char *p;

    //찾는 내용 있는지 검사
    while(!feof(employee_fp))
    {
        memset(send_tmp, 0, BUF_SIZE);
        memset(str_tmp, 0 , BUF_SIZE); 
        fgets(str_tmp,BUF_SIZE,employee_fp);    //맨 첫줄 제외 
        
        str_tmp[strlen(str_tmp)] = '\0';
        strcpy(send_tmp,str_tmp);

        p = strtok(str_tmp," \n");

        while(p != NULL)
        {
            if(!strcmp(p,buf))               //검색 요청사항이 있으면  
            {
                printf("%s",str_tmp);
                secure_write(socketfd,send_tmp,BUF_SIZE);    //정보 전부 전달
                break;
            }
            p=strtok(NULL, " \n");
        }
    }
    memset(buf,0,BUF_SIZE);
    secure_write(socketfd,"파일 끝 도달",BUF_SIZE);

    fclose(employee_fp);

}
/*
    사원 정보 삭제 구간
*/
void Employee_Delete()
{
    int check=0;
    memset(buf,0,BUF_SIZE);
    char delete[BUF_SIZE] = {0,};
    strcpy(delete,secure_read(socketfd,delete,BUF_SIZE));

    FILE *employee_fp; 
    if((employee_fp = fopen(EMPLOYEE_LIST,"a+t")) == NULL)        //Userlist 파일 open
    {
        fprintf(stderr,"fopen error!\n");
        return;
    }

    FILE *temp_fp;
    if((temp_fp = fopen("./temp.txt","w+t")) == NULL)        //Userlist 파일 open
    {
        fprintf(stderr,"fopen error\n");
        exit(-1);
    }

    char str_tmp2[BUF_SIZE]  = {0,};        //삭제안하는 것
    char delete_tmp[BUF_SIZE] = {0,};       //삭제하는 것
    char delete_depart[BUF_SIZE] = {0,};    //삭제하는 부서
    char str_tmp[BUF_SIZE];                 //읽어오는 것


    //찾는 내용 있는지 검사
    while(!feof(employee_fp))
    {
        memset(str_tmp, 0 , BUF_SIZE); 
        
        fgets(str_tmp,BUF_SIZE,employee_fp);    
        strcpy(str_tmp2,str_tmp);
        
        char *p = strtok(str_tmp," \n");
        
        if(p==NULL) break;
        strcpy(delete_depart,p); //삭제된 부서 저장
        p = strtok(NULL," \n");
        p = strtok(NULL," \n");

        if(!strcmp(p,delete))               //검색 요청사항이 있으면
        {
            strcpy(delete_tmp,str_tmp2);    //삭제 내용 저장  
            check = 1;                  //삭제한 놈 있음을 check
        }
        else
        {
            //삭제하는 것 발견 못했을때
            fwrite(str_tmp2,1,strlen(str_tmp2),temp_fp);        //삭제안하는 것 다시 쓰기
        }
 
    }
    fclose(employee_fp);
    fclose(temp_fp);
    system("rm employee_data.txt");
    system("mv temp.txt employee_data.txt");
    
    if(check)
    {
        strncat(delete_depart,".txt",4);                          //부서명.txt로 만듬

        FILE * department_fp;
        if((department_fp = fopen(delete_depart,"a+t")) == NULL)              //부서파일 open
        {
            fprintf(stderr,"fopen error\n");
            exit(-1);
        }
        FILE *temp_fp;
        if((temp_fp = fopen("./temp.txt","wt")) == NULL)        //Userlist 파일 open
        {
            fprintf(stderr,"fopen error\n");
            exit(-1);
        }
        //찾는 내용 있는지 검사
        while(!feof(department_fp))
        {
            memset(str_tmp, 0 , BUF_SIZE); 
            
            fgets(str_tmp,BUF_SIZE,department_fp);    

            if(!strcmp(str_tmp,delete_tmp))               //삭제 요청사항이 있으면  
            {
                continue;
            }
            else
            {
                //삭제하는 것 빼고 write
                fwrite(str_tmp,1,strlen(str_tmp),temp_fp);    
            }
    
        }
        fclose(department_fp);
        fclose(temp_fp);

        char delete_txt[BUF_SIZE] = {0,};
        strcpy(delete_txt,"rm ");
        strcat(delete_txt,delete_depart);

        char rename_txt[BUF_SIZE] ={0,};
        strcpy(rename_txt,"mv temp.txt ");
        strcat(rename_txt,delete_depart);

        system(delete_txt);
        system(rename_txt);
        printf("Client가 요청한 사원 삭제를 성공했습니다.\n");
        secure_write(socketfd,"삭제를 성공했습니다.",BUF_SIZE);
    }
    else
    {
        printf("Client가 없는 data를 요청했습니다.\n");
        secure_write(socketfd,"존재하지 않는 사원입니다.",BUF_SIZE);
    }
    

}

int server_section()
{
    char section_mode[BUF_SIZE] = {0,};
    
    while(1)
    {
        memset(section_mode,0,BUF_SIZE);
        strcpy(section_mode,secure_read(socketfd,section_mode,sizeof(section_mode))); //client로 부터 mode 읽어옴
        printf("Section mode : %s\n",section_mode);  
              
        sleep(1);

        if(!strcmp(section_mode,"employee registration"))
        {
            printf("admin이 사원 등록을 요청했습니다.\n");
            printf("사원 등록구간에 진입합니다.\n");

            Employee_Registration();                        //사원 등록 구간
        }
        else if (!strcmp(section_mode,"Department Information"))
        {   

            printf("admin이 부서 정보 조회를 요청했습니다.\n");
            printf("부서 정보 조회구간에 진입합니다.\n");

            Department_Information();                           //부서 정보 출력 구간
        }
        else if (!strcmp(section_mode,"Employee Search"))
        {

            printf("admin이 사원 정보 조회를 요청했습니다.\n");
            printf("사원 정보 조회구간에 진입합니다.\n");

            Employee_Search();                                  //사원 정보 조회 구간
     
        }
        else if(!strcmp(section_mode,"Employee Delete"))
        {

            printf("admin이 사원 정보 삭제을 요청했습니다.\n");
            printf("사원 정보 삭제구간에 진입합니다.\n");

            memset(buf,0,BUF_SIZE);
            Employee_Delete();

        }
        else if(!strcmp(section_mode,"log out"))
        {
            secure_write(socketfd,"ok",BUF_SIZE);
            break;
        }
        else if(!strcmp(section_mode,"exit"))
        {
            secure_write(socketfd,"ok",BUF_SIZE);
            printf("Client가 연결 종료를 요청하였습니다.\n");
            printf("Client와의 연결을 종료합니다.\n");
            printf("program을 종료합니다.\n");
            
            close(socketfd);            //socket
            close(server_socketfd);     //close
            sleep(1);
            exit(1);                    //server 종료
        }
        
    }
}

void Server()
{
 char mode[BUF_SIZE]={0,};
   
    while(1)
    {
        memset(mode,0,BUF_SIZE);
        strcpy(mode,secure_read(socketfd,mode,sizeof(mode))); //client로 부터 mode 읽어옴
        printf("mode : %s\n",mode);


        if(!strcmp(mode,"sign_up")){    //회원가입일시,

            printf("Sign_up\n");
            if(!Sign_up())              //client 강제종료 당했으면 server routine 종료
            {    
                printf("Client와의 연결을 종료합니다.\n");
                printf("program을 종료합니다.\n");
                
                close(socketfd);
                close(server_socketfd);
                sleep(1);
                exit(1);
            } 
        }   
        else if(!strcmp(mode,"sign_in"))        //login 일 시,
        {
                                                      
            if(sign_in())
            {
                int check = 0;
                check = server_section();             //client가 로그인 성공 시 section 진입 

                if(check == 6)     //client가 log out 요청
                    continue;
                
            }
        }
        else if(!strcmp(mode,"exit")){//프로그램 종료일때,
            secure_write(socketfd,"okay",BUF_SIZE);       //error 발생안한 것 체크용
            
            printf("Client가 연결 종료를 요청하였습니다.\n");
            printf("Client와의 연결을 종료합니다.\n");
            printf("program을 종료합니다.\n");
            
            close(socketfd);
            close(server_socketfd);
            sleep(1);
            exit(1);
            
        }

        else 
        {
            printf("error!\n");
            secure_write(socketfd,"error발생",BUF_SIZE);
            continue;
        }    
   }

}
/*
    RSA key 생성 함수
*/
void RSA_key_generator(RSA** rsa_object, int bits)
{
    BIGNUM * e = NULL;
    e = BN_new();
    if(BN_set_word(e, RSA_F4) != 1) 
    {
        fprintf(stderr,"BN_set_word error!\n");
        exit(-1);
    }
 
    *rsa_object = RSA_new();
    if(RSA_generate_key_ex(*rsa_object, 2048,e ,NULL) !=1) // RSA 키 생성
    {
        BN_free(e);
        fprintf(stderr,"RSA key generate fail!\n");
        exit(-1);
    }


	//RSA 키쌍에서 공개키를 추출
	rsa_pub = RSAPublicKey_dup(*rsa_object); 
	if(!rsa_pub)
	{
		fprintf(stderr,"pub key generate error!");
		exit(-1);
	}

	//public key 저장을 위한 public.pem 파일 생성
	FILE *pub_fp = fopen("public.pem", "wb"); 
	if(!pub_fp)
	{
        fprintf(stderr, "fopen error!\n");
        exit(-1);
	}

 	//public.pem 파일에 개인키 저장
	if(PEM_write_RSAPublicKey(pub_fp, rsa_pub) < 0)
	{
		fprintf(stderr,"PEM_write_RSAPubliceKey error!");
		exit(-1);
	}   
    fclose(pub_fp);
	
	//개인키 저장을 위한 PRV.pem 파일 생성
	FILE *fp = fopen("private.pem", "wb"); 
	if(!fp)
	{
        fprintf(stderr, "fopen error!\n");
        exit(-1);
	}


	//private.pem 파일에 개인키 저장
	if(PEM_write_RSAPrivateKey(fp, *rsa_object, NULL, NULL, 0, NULL, NULL) < 0)
	{
		fprintf(stderr,"PEM_write_RSAPrivateKey error!");
		exit(-1);
	}
    fclose(fp);    
}


// socket 연결 함수
void secure_socket_init()
{
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    server_bio = BIO_new_accept(HOSTADDRESS); // 새로운 BIO 접근 만든다.
   
    RSA_key_generator(&rsa_object,2048);    //RSA key 생성
}

/*
    연결 listen함수이자, 키교환 이루어지는 함수 
*/
void connect_listen()
{                   
    printf("connection listening..\n");
    
    BIO_do_accept(server_bio);          //binding

    if (BIO_do_accept(server_bio) <= 0) // 클라이언트의 연결 요청을 기다림 --> 키교환 채널
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    char encrypted_key[BUF_SIZE] = {0,};
    char encrypted_iv[BUF_SIZE] = {0,}; 

    client_bio = BIO_pop(server_bio); // 접속이 완료되면 이 부분 통과(accept부분)  
    printf("Client Connected, send public key to client...\n");

    int n = 0;
    //n = PEM_write_bio_RSA_PUBKEY(client_bio, rsa_object); // 공개키를 클라이언트에게 전송

    FILE * fp = fopen("public.pem", "rb");
    if(!fp)
	{
		fprintf(stderr,"fopen error!");
		exit(-1);
	}

	//파일의 사이즈 저장
	fseek(fp, 0L, SEEK_END);
	unsigned long seek=ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	unsigned long size =htonl(seek);    

    n = BIO_write(client_bio, &size,sizeof(size));
    assert(n >=0);

    unsigned char c;
	//public.pem의 내용을 한 바이트씩 사이즈만큼 전송
	for(int i=0;i<= seek;i++){
		fread(&c, sizeof(unsigned char), 1, fp); 
		BIO_write(client_bio, &c, sizeof(c));	
	}

	fclose(fp);
    sleep(1);    
    n = BIO_read(client_bio, encrypted_key, BUF_SIZE); // 클라이언트로부터 공개키로 암호화한 AES Key를 수신함
    
    RSA_private_decrypt(n, encrypted_key, aes_key, rsa_object, RSA_PKCS1_OAEP_PADDING); // 개인키로 암호화된 AES Key를 복호화함
    

    printf("Recieved Symmetric Key : ");
    for(int i=0;i<32;i++)
        printf("%02X ",(unsigned char)aes_key[i]); // 복호화된 AES Key를 출력함
    printf("\n");
    
    n = BIO_read(client_bio, encrypted_iv, BUF_SIZE); // 클라이언트로부터 공개키로 암호화한 AES iv를 수신함
 
    RSA_private_decrypt(n, encrypted_iv, iv, rsa_object, RSA_PKCS1_OAEP_PADDING); // 개인키로 암호화된 AES iv를 복호화함
    
    printf("Recieved AES iv : ");
    for(int i=0;i<16;i++)
        printf("%02X ",(unsigned char)iv[i]); // 복호화된 AES iv를 출력함
    printf("\n");
                
    // 키 교환 완료. AES 암호화 통신 시작

    RSA_free(rsa_object);   //rsa 는 안씀으로 free
    BIO_free(client_bio);   //키교환 채널 닫음
    BIO_free(server_bio);

    printf("키 교환 채널을 닫고 일반 채널을 여는중..\n");
    sleep(1);

    int client_addr_size = 0;
    char buf[BUF_SIZE] = { 0, };

    //일반 통신 채널 다시 열기
    if ((server_socketfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "socket error!!\n");
        exit(-1);
    }

    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;                //IPv4 Internet protocol
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); //32bit IPV4 address
    server_addr.sin_port = htons(HOSTPORT);              //I use 4000 port num

    //bind 함수
    if (bind(server_socketfd, (struct sockaddr*) & server_addr, sizeof(server_addr)) == -1)
    {
        fprintf(stderr, "bind error!\n");
        exit(-1);
    }

    //client의 요청 기다림
    if (listen(server_socketfd, 2) == -1) {
        fprintf(stderr, "listen error!\n");
        exit(-1);
    }

    //accept함수
    client_addr_size = sizeof(client_addr);
    if ((socketfd = accept(server_socketfd, (struct sockaddr*) & client_addr, &client_addr_size)) < 0)
    {
        fprintf(stderr, "accept error!\n");
        exit(-1);
    }
    printf("Client와의 일반 통신 채널열렸습니다.\n");
}