CC = gcc
CFLAG = -g -o 
LDFLAGS = -lssl -lcrypto
OBJS = server.c common.h
TARGET = server


$(TARGET): $(OBJS)
	$(CC) $(CFLAG) $@ $(OBJS) $(LDFLAGS)

clean:
	rm -rf $(TARGET) *.pem

clean_all:		#모든 user, admin list 삭제
	rm -rf *.txt $(TARGET) *.pem *.csv

install:			#sudo 권한 필요
	apt install openssl libssl1.0.0 libssl-dev libcrypto++-dev