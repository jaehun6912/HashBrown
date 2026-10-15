#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 10101
#define BUF_SIZE 512

int main() {
    int sock;
    struct sockaddr_in serv_adr;
    char buf[BUF_SIZE];
    char ip[30];

    // 프로그램 실행 후 접속할 서버의 IP 주소만 입력받기
    printf("접속할 IP 주소 입력: ");
    scanf("%s", ip);

    // [중요] scanf 이후 입력 버퍼에 남은 엔터('\n')를 비워주어야 fgets가 정상 동작합니다.
    while (getchar() != '\n');

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket error");
        exit(1);
    }

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = inet_addr(ip); // 사용자가 입력한 IP 주소 적용
    serv_adr.sin_port = htons(PORT);          // 포트 10101 고정 적용

    if (connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1) {
        perror("connect error");
        exit(1);
    } else {
        printf("(%s:%d)연결됨.\n", ip, PORT);
    }

    // 문장 입력 및 서버 전송 (write)
    while (1) {
        printf("전송할 메시지 입력 (종료: Q 또는 q): ");
        fgets(buf, BUF_SIZE, stdin);
        
        if (!strcmp(buf, "q\n") || !strcmp(buf, "Q\n"))
            break;

        write(sock, buf, strlen(buf));
    }

    close(sock);
    return 0;
}