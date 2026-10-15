#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFFER_SIZE 4096

int sock;

void do_put(const char *filepath) {
    // 파일 열기
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        printf("파일을 열 수 없습니다: %s\n", filepath);
        return;
    }

    // 파일 크기 계산
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // 파일명 추출 (경로 포함 가능)
    char *basename_ptr = strrchr(filepath, '/');
    const char *filename = basename_ptr ? basename_ptr + 1 : filepath;

    printf("\nFile_name: %s\n", filename);
    printf("File_size: %ld byte\n\n", filesize);

    // 명령어 전송
    char command[16] = "put";
    send(sock, command, sizeof(command), 0);

    // 파일명 전송
    char fname_buf[256];
    strncpy(fname_buf, filename, sizeof(fname_buf));
    send(sock, fname_buf, sizeof(fname_buf), 0);

    // 파일 크기 전송
    send(sock, &filesize, sizeof(filesize), 0);

    // 파일 데이터 전송
    printf("%s 업로드\n", filename);
    char buf[BUFFER_SIZE];
    int n;
    long sent = 0;
    while ((n = fread(buf, 1, BUFFER_SIZE, fp)) > 0) {
        send(sock, buf, n, 0);
        sent += n;
    }
    fclose(fp);

    // 서버 응답 대기
    char ack[16];
    recv(sock, ack, sizeof(ack), 0);
    printf("========[업로드 완료]=======\n");
}

void do_get(const char *filename) {
    // 명령어 전송
    char command[16] = "get";
    send(sock, command, sizeof(command), 0);

    // 파일명 전송
    char fname_buf[256];
    strncpy(fname_buf, filename, sizeof(fname_buf));
    send(sock, fname_buf, sizeof(fname_buf), 0);

    // 파일 크기 수신
    long filesize;
    recv(sock, &filesize, sizeof(filesize), 0);

    if (filesize < 0) {
        printf("서버에 해당 파일이 없습니다: %s\n", filename);
        return;
    }

    printf("\nFile_name: %s\n", filename);
    printf("File_size: %ld byte\n\n", filesize);

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("파일 저장 실패");
        return;
    }

    char buf[BUFFER_SIZE];
    long received = 0;
    int n;
    printf("%s 다운로드 중...\n", filename);
    while (received < filesize) {
        int to_read = (filesize - received < BUFFER_SIZE) ? (filesize - received) : BUFFER_SIZE;
        n = recv(sock, buf, to_read, 0);
        if (n <= 0) break;
        fwrite(buf, 1, n, fp);
        received += n;
    }
    fclose(fp);
    printf("========[다운로드 완료]=======\n");
}

int main(int argc, char *argv[]) {
    char server_ip[64];
    int port;

    printf("접속할 서버 주소(종료 : exit): ");
    scanf("%s", server_ip);
    if (strcmp(server_ip, "exit") == 0) return 0;

    printf("포트번호 :");
    scanf("%d", &port);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        printf("잘못된 IP 주소: %s\n", server_ip);
        return 1;
    }

    // 연결 테스트 (접속 가능 여부 확인용)
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("서버 연결 실패");
        return 1;
    }
    close(sock); // 테스트 연결 종료, 이후 명령마다 재연결

    printf("[%s:%d 서버에 연결됨]\n", server_ip, port);

    char command[64];
    char filename[256];

    while (1) {
        printf("명령어 입력 [put, get] (종료: exit): ");
        fflush(stdout);
        scanf("%s", command);

        if (strcmp(command, "exit") == 0) {
            break;
        } else if (strcmp(command, "put") == 0) {
            printf("업로드 할 파일명을 입력해주세요 :");
            fflush(stdout);
            scanf("%s", filename);

            // 명령마다 새 연결
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("서버 재연결 실패");
                close(sock);
                continue;
            }
            do_put(filename);
            close(sock);

        } else if (strcmp(command, "get") == 0) {
            printf("다운로드 할 파일명을 입력해주세요 :");
            fflush(stdout);
            scanf("%s", filename);

            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("서버 재연결 실패");
                close(sock);
                continue;
            }
            do_get(filename);
            close(sock);

        } else {
            printf("알 수 없는 명령입니다. put / get / exit 중 입력하세요.\n");
        }
    }

    printf("연결 종료.\n");
    return 0;
}
