#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define PORT 12345
#define BUFFER_SIZE 4096

void handle_put(int client_sock)
{
    char filename[256];
    long filesize;
    memset(filename, 0, sizeof(filename)); // 쓰레기값 방지

    // 파일명 수신
    recv(client_sock, filename, sizeof(filename), 0);

    // 파일 크기 수신
    recv(client_sock, &filesize, sizeof(filesize), 0);
    printf("%s size : %ld\n", filename, filesize);
    fflush(stdout);

    // 실제 파일명에서 경로 제거 (보안)
    char *basename_ptr = strrchr(filename, '/');
    char *safe_name = basename_ptr ? basename_ptr + 1 : filename;

    // 저장 경로 설정
    char save_path[512];
    snprintf(save_path, sizeof(save_path), "./received/%s", safe_name);

    // received 디렉토리 생성
    mkdir("./received", 0755);

    FILE *fp = fopen(save_path, "wb");
    if (!fp)
    {
        perror("파일 열기 실패");
        return;
    }

    char buf[BUFFER_SIZE];
    long received = 0;
    int n;
    while (received < filesize)
    {
        int to_read = (filesize - received < BUFFER_SIZE) ? (filesize - received) : BUFFER_SIZE;
        n = recv(client_sock, buf, to_read, 0);
        if (n <= 0)
            break;
        fwrite(buf, 1, n, fp);
        received += n;
    }
    fclose(fp);

    printf("\n%s / save success\n", safe_name);
    fflush(stdout);

    // 완료 응답 전송
    char *ack = "OK";
    send(client_sock, ack, strlen(ack) + 1, 0);
}

void handle_get(int client_sock)
{
    char filename[256];
    memset(filename, 0, sizeof(filename)); // 쓰레기값 방지

    recv(client_sock, filename, sizeof(filename), 0);

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "./received/%s", filename);

    FILE *fp = fopen(filepath, "rb");
    if (!fp)
    {
        // 파일 없음 알림
        long err = -1;
        send(client_sock, &err, sizeof(err), 0);
        printf("파일 없음: %s\n", filename);
        return;
    }

    // 파일 크기 계산
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    send(client_sock, &filesize, sizeof(filesize), 0);

    char buf[BUFFER_SIZE];
    int n;
    while ((n = fread(buf, 1, BUFFER_SIZE, fp)) > 0)
    {
        send(client_sock, buf, n, 0);
    }
    fclose(fp);

    printf("%s 전송 완료 (%ld bytes)\n", filename, filesize);
}

int main()
{
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("소켓 생성 실패");
        exit(1);
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("바인드 실패");
        exit(1);
    }

    listen(server_sock, 5);
    printf("서버 대기 중 ...\n");

    while (1)
    {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0)
        {
            perror("accept 실패");
            continue;
        }

        // 명령어 수신 (배열 초기화 후 정확히 16바이트 모두 읽기)
        char command[16];
        memset(command, 0, sizeof(command));

        int recv_len = recv(client_sock, command, sizeof(command), 0);

        // 클라이언트가 연결 테스트만 하고 끊었거나 에러가 난 경우 예외 처리
        if (recv_len <= 0)
        {
            close(client_sock);
            continue;
        }

        printf("클라이언트 접속\n");
        printf("Client Command: %s\n", command);
        fflush(stdout);

        if (strcmp(command, "put") == 0)
        {
            handle_put(client_sock);
        }
        else if (strcmp(command, "get") == 0)
        {
            handle_get(client_sock);
        }
        else
        {
            printf("알 수 없는 명령: %s\n", command);
        }

        close(client_sock);
        printf("\n");
    }

    close(server_sock);
    return 0;
}