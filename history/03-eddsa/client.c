#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 65536
#define NAME_SIZE 256
#define COMMAND_SIZE 16
#define ACK_SIZE 16
#define ED25519_SIG_LEN 64
#define CLIENT_PRIVATE_KEY "client_private.pem"
#define SERVER_PUBLIC_KEY "server_public.pem"
#define FILE_DIR "Files"

typedef struct {
    long filesize;
    int sign_len;
    unsigned char hash[SHA256_DIGEST_LENGTH];
} File_Info;

typedef struct {
    char filename[NAME_SIZE];
    long filesize;
    unsigned char hash[SHA256_DIGEST_LENGTH];
} Signed_Info;

extern int eddsa_sign_with_key(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len, const char *key_path);
extern int eddsa_verify_with_key(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len, const char *key_path);

static int sock;

static int send_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0) return 0;
        p += n;
        len -= (size_t)n;
    }
    return 1;
}

static int recv_all(int fd, void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n <= 0) return 0;
        p += n;
        len -= (size_t)n;
    }
    return 1;
}

static const char *path_basename(const char *path) {
    const char *base = path;
    const char *slash = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    if (slash) base = slash + 1;
    if (backslash && backslash + 1 > base) base = backslash + 1;
    return base;
}


static int ensure_files_dir(void) {
    if (mkdir(FILE_DIR, 0755) < 0 && errno != EEXIST) {
        printf("Files 디렉토리 생성 실패: %s\n", strerror(errno));
        return 0;
    }
    return 1;
}

static int build_file_path(char *out, size_t out_size, const char *filename) {
    const char *safe_name = path_basename(filename);
    if (safe_name[0] == '\0') return 0;
    return snprintf(out, out_size, "%s/%s", FILE_DIR, safe_name) < (int)out_size;
}

static int read_line(char *buf, size_t size) {
    if (!fgets(buf, size, stdin)) return 0;
    buf[strcspn(buf, "\r\n")] = 0;
    return 1;
}

static void print_hash(const unsigned char hash[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02X", hash[i]);
}

static void print_signature_preview(const unsigned char *sig, size_t sig_len) {
    size_t show_len = sig_len < 16 ? sig_len : 16;
    for (size_t i = 0; i < show_len; i++) printf("%02X", sig[i]);
    if (sig_len > show_len) printf("...");
}

static void make_signed_info(Signed_Info *out, const char *filename, long filesize, const unsigned char hash[SHA256_DIGEST_LENGTH]) {
    memset(out, 0, sizeof(*out));
    strncpy(out->filename, filename, NAME_SIZE - 1);
    out->filesize = filesize;
    memcpy(out->hash, hash, SHA256_DIGEST_LENGTH);
}

static int file_sha256(FILE *fp, long *filesize, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    unsigned char buf[BUFFER_SIZE];
    unsigned int hash_len = 0;
    int ok = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0) goto done;
    if (fseek(fp, 0, SEEK_END) != 0) goto done;
    *filesize = ftell(fp);
    if (*filesize < 0 || fseek(fp, 0, SEEK_SET) != 0) goto done;

    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) <= 0) goto done;
    }
    if (ferror(fp)) goto done;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) <= 0 || hash_len != SHA256_DIGEST_LENGTH) goto done;
    ok = fseek(fp, 0, SEEK_SET) == 0;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int send_file_data(FILE *fp, long filesize) {
    unsigned char buf[BUFFER_SIZE];
    long sent = 0;
    while (sent < filesize) {
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n == 0 || !send_all(sock, buf, n)) return 0;
        sent += (long)n;
    }
    return sent == filesize;
}

static int recv_file_data(FILE *fp, long filesize, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    unsigned char buf[BUFFER_SIZE];
    unsigned int hash_len = 0;
    long received = 0;
    int ok = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0) goto done;
    while (received < filesize) {
        size_t n = (filesize - received < BUFFER_SIZE) ? (size_t)(filesize - received) : BUFFER_SIZE;
        if (!recv_all(sock, buf, n)) goto done;
        if (fwrite(buf, 1, n, fp) != n) goto done;
        if (EVP_DigestUpdate(ctx, buf, n) <= 0) goto done;
        received += (long)n;
    }
    ok = EVP_DigestFinal_ex(ctx, hash, &hash_len) > 0 && hash_len == SHA256_DIGEST_LENGTH;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

void do_put(const char *filepath) {
    if (!ensure_files_dir()) return;

    const char *filename = path_basename(filepath);
    char file_path[512];
    if (!build_file_path(file_path, sizeof(file_path), filename)) {
        printf("잘못된 파일명입니다: %s\n", filepath);
        return;
    }

    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        printf("파일을 열 수 없습니다: %s\n", file_path);
        return;
    }

    long filesize = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!file_sha256(fp, &filesize, hash)) {
        printf("파일 해시 계산 실패\n");
        fclose(fp);
        return;
    }

    Signed_Info signed_info;
    unsigned char *sign = NULL;
    size_t sign_len = 0;
    make_signed_info(&signed_info, filename, filesize, hash);
    if (!eddsa_sign_with_key((unsigned char *)&signed_info, sizeof(signed_info), &sign, &sign_len, CLIENT_PRIVATE_KEY)) {
        printf("서명 생성 실패\n");
        fclose(fp);
        return;
    }

    char command[COMMAND_SIZE] = "up";
    char fname_buf[NAME_SIZE] = {0};
    File_Info info = {0};
    strncpy(fname_buf, filename, sizeof(fname_buf) - 1);
    info.filesize = filesize;
    info.sign_len = (int)sign_len;
    memcpy(info.hash, hash, SHA256_DIGEST_LENGTH);

    int ok = send_all(sock, command, sizeof(command)) &&
             send_all(sock, fname_buf, sizeof(fname_buf)) &&
             send_all(sock, &info, sizeof(info)) &&
             send_all(sock, sign, sign_len) &&
             send_file_data(fp, filesize);

    printf("\n[업로드 서명 생성]\n");
    printf("파일: %s (%1ld byte)\n", filename, filesize);
    //printf("파일 크기: %ld byte\n", filesize);
    printf("서명 대상: [파일명 + 파일크기 + 파일 전체 SHA-256]\n");
    printf("서명 대상 SHA-256 해시값: ");
    print_hash(hash);
    printf("\n사용 개인키: %s\n", CLIENT_PRIVATE_KEY);
    printf("생성된 디지털 서명(Ed25519): ");
    print_signature_preview(sign, sign_len);
    printf("\n전송 결과: %s\n\n", ok ? "완료" : "실패");

    free(sign);
    fclose(fp);
    if (!ok) {
        printf("========[업로드 실패]=======\n\n");
        return;
    }

    char ack[ACK_SIZE] = {0};
    if (!recv_all(sock, ack, sizeof(ack)) || strcmp(ack, "OK") != 0) {
        printf("========[업로드(검증) 실패]=======\n\n");
    } else {
        printf("========[업로드(검증) 완료]=======\n\n");
    }
}

void do_get(const char *filename) {
    char command[COMMAND_SIZE] = "down";
    char fname_buf[NAME_SIZE] = {0};
    strncpy(fname_buf, filename, sizeof(fname_buf) - 1);

    if (!send_all(sock, command, sizeof(command)) || !send_all(sock, fname_buf, sizeof(fname_buf))) {
        printf("요청 전송 실패\n");
        return;
    }

    File_Info info;
    if (!recv_all(sock, &info, sizeof(info)) || info.filesize < 0) {
        printf("서버에 해당 파일이 없습니다: %s\n", filename);
        return;
    }
    if (info.sign_len != ED25519_SIG_LEN) {
        printf("잘못된 서명 길이 수신\n");
        return;
    }

    unsigned char sign[ED25519_SIG_LEN];
    if (!recv_all(sock, sign, sizeof(sign))) {
        printf("서명 수신 실패\n");
        return;
    }

    if (!ensure_files_dir()) return;

    const char *save_name = path_basename(filename);
    char save_path[512], tmp_name[520];
    if (!build_file_path(save_path, sizeof(save_path), save_name)) {
        printf("잘못된 파일명입니다: %s\n", filename);
        return;
    }
    snprintf(tmp_name, sizeof(tmp_name), "%s.tmp", save_path);

    FILE *fp = fopen(tmp_name, "wb");
    if (!fp) {
        perror("파일 저장 실패");
        return;
    }

    unsigned char recv_hash[SHA256_DIGEST_LENGTH];
    int ok = recv_file_data(fp, info.filesize, recv_hash);
    fclose(fp);

    Signed_Info signed_info;
    make_signed_info(&signed_info, save_name, info.filesize, info.hash);
    int hash_ok = ok && memcmp(recv_hash, info.hash, SHA256_DIGEST_LENGTH) == 0;
    int sign_ok = hash_ok && eddsa_verify_with_key((unsigned char *)&signed_info, sizeof(signed_info), sign, sizeof(sign), SERVER_PUBLIC_KEY);
    int save_ok = sign_ok && rename(tmp_name, save_path) == 0;

    printf("\n[다운로드 서명 검증]\n");
    printf("파일: %s (%1ld byte)\n", filename, info.filesize);
    //printf("파일 크기: %ld byte\n", info.filesize);
    printf("검증 대상: [파일명 + 파일크기 + 파일 전체 SHA-256]\n");
    printf("수신 파일 SHA-256 해시값: ");
    print_hash(recv_hash);
    printf("\n서명 대상 SHA-256 해시값: ");
    print_hash(info.hash);
    printf("\n사용 공개키: %s\n", SERVER_PUBLIC_KEY);
    printf("수신된 디지털 서명(Ed25519): ");
    print_signature_preview(sign, sizeof(sign));
    printf("\n해시 비교 결과: %s\n", hash_ok ? "일치" : "불일치");
    printf("서명 검증 결과: %s\n", sign_ok ? "성공" : "실패");
    printf("저장 결과: %s\n\n", save_ok ? "성공" : "실패");

    if (save_ok) {
        printf("========[다운로드(검증) 완료]=======\n\n");
    } else {
        remove(tmp_name);
        printf("========[다운로드(검증) 실패]=======\n\n");
    }
}

int main(void) {
    char server_ip[64], port_text[16], command[64], filename[NAME_SIZE];
    int port;
    struct sockaddr_in server_addr;

    printf("접속할 서버 주소(종료 : exit): ");
    if (!read_line(server_ip, sizeof(server_ip)) || strcmp(server_ip, "exit") == 0) return 0;
    printf("포트번호: ");
    if (!read_line(port_text, sizeof(port_text))) return 1;
    port = atoi(port_text);
    if (port <= 0 || port > 65535) {
        printf("잘못된 포트번호: %s\n", port_text);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        printf("잘못된 IP 주소: %s\n", server_ip);
        return 1;
    }

    if (!ensure_files_dir()) return 1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("서버 연결 실패: %s\n", strerror(errno));
        close(sock);
        return 1;
    }
    printf("[%s:%d  연결됨]\n\n", server_ip, port);

    while (1) {
        printf("명령어 입력 [up / down] (종료: exit): ");
        fflush(stdout);
        if (!read_line(command, sizeof(command))) break;

        if (strcmp(command, "exit") == 0) {
            char exit_command[COMMAND_SIZE] = "exit";
            send_all(sock, exit_command, sizeof(exit_command));
            break;
        }

        if (strcmp(command, "up") != 0 && strcmp(command, "down") != 0) {
            printf("잘못된 명령입니다. 다시 입력하세요.\n");
            continue;
        }

        printf("\n%s 할 파일명을 입력하세요: ", strcmp(command, "up") == 0 ? "업로드" : "다운로드");
        fflush(stdout);
        if (!read_line(filename, sizeof(filename))) break;
        if (filename[0] == 0) {
            printf("파일명을 입력하세요.\n");
            continue;
        }

        if (strcmp(command, "up") == 0) do_put(filename);
        else do_get(filename);
    }

    close(sock);
    printf("연결 종료\n");
    return 0;
}
