#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 10101
#define BUF_SIZE 512

int main() {
    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    socklen_t clnt_adr_sz;
    char buf[BUF_SIZE];
    int str_len;

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        perror("socket error");
        exit(1);
    }

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(PORT); // 포트 10101 고정 적용

    if (bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1) {
        perror("bind error");
        exit(1);
    }

    if (listen(serv_sock, 5) == -1) {
        perror("listen error");
        exit(1);
    }
    
    printf("클라이언트 접속 대기 (포트: %d)...\n", PORT);

    clnt_adr_sz = sizeof(clnt_adr);
    clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
    if (clnt_sock == -1) {
        perror("accept error");
        exit(1);
    } else {
        printf("클라이언트 접속됨.\n");
    }

    // 데이터 수신 및 출력
    while ((str_len = read(clnt_sock, buf, BUF_SIZE)) > 0) {
        buf[str_len] = '\0';
        printf("클라이언트로부터 수신된 메시지: %s", buf);
    }

    close(clnt_sock);
    close(serv_sock);
    
    return 0;
}