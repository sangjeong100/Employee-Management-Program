# Employee Management Program
personal project of System Software Security and Practice

## 1. 목적
*	회사에서 직원들의 목록을 관리하는 것은 필수요소이다. 이를 위해서 각 회사마다 직원들의 정보를 관리하는 DataBase를 가지고 있다. 그리고 DataBase를 바탕으로 신입사원 채용이나, 직원들의 연봉협상, 부서이동 등의 업무를 할 수 있다. 이 프로그램은 직원 관리자들에게 이러한 기능을 제공하고자, 만든 프로그램이다. 

## 2. 기능 
1. **암/복호화 키 생성 및 전달**
  - Server의 RSA Key 생성 및 공개 키 전달 (Bio Socket 활용)
  - Client의 AES Key 생성 및 RSA를 통한 AES key 교환 (Bio Socket 활용)
  - 교환한 AES256 키를 이용하여 암호화 통신
  
  
2. **Socket을 통한 Server - Client 통신 프로그램**
  - **회원가입** 
    - Client가 server에게 회원가입 요청
    - Server는 client에게 admin_key를 입력 받음 (admin_key : 1011) 
       - admin_key 맞으면, 회원가입 허용 
       - admin_key 틀리면, 회원가입 거부
       - admin_key 5회틀리면, Admin 자격이 없다는 메시지와 함께 Client종료 및 Server종료
    - 회원가입 허용 시, ID, PW, admin이름을 입력 받음 
        - ID 중복 허용 X
        - ID 중복이 없으면 admin_data.csv에 회원 정보를 저장하고 client 메뉴로 복귀
        - ID 중복시, 회원 정보를 저장하지 않고 Client 메뉴로 복귀
        
  - **로그인**
    - Server가 Client로부터 ID, PW 입력받음 
        - 로그인 기회 5번
        - ID와 PW, 둘 중 하나 틀리면 로그인 기회를 줄임
        - 5회틀리면, 로그인세션을 60초동안 막고, SIGINT를 막음
       - 로그인 성공 시, DB 관레 메뉴로 이동
       - Admin이 하나도 등록되지 않았으면, 이전 메뉴로 복귀시킴     

 - **DB관리 메뉴**
     - 사원 등록
        - 사원의 부서, 이름, 사원 번호, 입사년도, 연봉 입력받고 employee_data.txt와 부서명.txt에 저장
        - 사원 번호는 고유한 번호이므로, 이미 존재하는 사원 번호이면, 오류문을 출력하고 등록을 막음
     - 부서 정보 조회
        - Admin에게 부서명을 입력받고, 부서명.txt의 내용을 보여줌
        - 부서목록 : 경영팀, 인사팀, 개발팀, 홍보팀
     - 사원 정보 조회
        - Admin에게 무슨 정보로 검색할 것인지 선택받음
            - 사원 이름, 사원 번호, 입사년도, 연봉
        - employee_data.txt에 일치하는 정보를 가진 사원을 모두 보여줌
    - 사원 정보 삭제      
        - Admin에게 사원 번호를 입력받고, 일치하는 사원이 있으면 삭제
    - 로그아웃
        - admin의 로그인을 종료하고, 이전 메뉴로 돌아감
    - 종료
        - Client와 Server의 연결을 끊고, 모두 종료


## 3. 추가 설치 (openssl)
- sudo make install (server 및 client 공통)


## 4. makefile 사용 방법
 1. server
    - make -> 실행파일 생성
    - make clean -> 실행파일 및 pem파일(RSA 공개키, 비밀키) 삭제
    - make clean_all -> 실행파일 및 pem파일, 그리고 모든 DB 파일 삭제
 2. client
    - make -> 실행파일 생성
    - make clean -> 실행파일 및 pem파일(RSA 공개키) 삭제
 
## 5. 실행 방법
- ./server "Your IP" "Your Port"
- ./client "Server IP" "Server Port"

## 6. 참고사이트
[openssl RSA 키 생성 참조](https://m.blog.naver.com/PostView.nhn?blogId=seongjeongki7&logNo=220904551133&proxyReferer=https:%2F%2Fwww.google.com%2F)

[C언어 password 입력 시 * 표시 참조](https://pwnbit.kr/44)

[Linux getch() 함수 구현](https://m.blog.naver.com/PostView.nhn?blogId=bsbs0126&logNo=150031869760&proxyReferer=https:%2F%2Fwww.google.com%2F)

[openssl 설치참조](https://tttsss77.tistory.com/107)

[BIO socket DOCS](https://linux.die.net/man/3/bio_do_accept)
