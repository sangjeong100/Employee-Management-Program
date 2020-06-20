CC = gcc
CFLAG = -g -o 
LDFLAGS = -lssl -lcrypto
OBJS = client.c common.h
TARGET = client


$(TARGET): $(OBJS)
	$(CC) $(CFLAG) $@ $(OBJS) $(LDFLAGS)

clean:
	rm -rf $(TARGET) *.pem

install:					##sudo 권한 필요
	apt install openssl libssl1.0.0 libssl-dev libcrypto++-dev libncurses5-dev