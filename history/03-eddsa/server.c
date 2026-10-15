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

#define PORT 10101
#define BUFFER_SIZE 65536
#define NAME_SIZE 256
#define COMMAND_SIZE 16
#define ACK_SIZE 16
#define ED25519_SIG_LEN 64
#define CLIENT_PUBLIC_KEY "client_public.pem"
#define SERVER_PRIVATE_KEY "server_private.pem"
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

static int valid_filename(const char *name) {
    return name[0] != '\0' && strcmp(name, ".") != 0 && strcmp(name, "..") != 0 && strstr(name, "..") == NULL;
}

static void send_ack(int fd, const char *value) {
    char ack[ACK_SIZE] = {0};
    strncpy(ack, value, sizeof(ack) - 1);
    send_all(fd, ack, sizeof(ack));
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

static int send_file_data(int fd, FILE *fp, long filesize) {
    unsigned char buf[BUFFER_SIZE];
    long sent = 0;
    while (sent < filesize) {
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n == 0 || !send_all(fd, buf, n)) return 0;
        sent += (long)n;
    }
    return sent == filesize;
}

static int recv_file_data(int fd, FILE *fp, long filesize, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    unsigned char buf[BUFFER_SIZE];
    unsigned int hash_len = 0;
    long received = 0;
    int ok = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0) goto done;
    while (received < filesize) {
        size_t n = (filesize - received < BUFFER_SIZE) ? (size_t)(filesize - received) : BUFFER_SIZE;
        if (!recv_all(fd, buf, n)) goto done;
        if (fwrite(buf, 1, n, fp) != n) goto done;
        if (EVP_DigestUpdate(ctx, buf, n) <= 0) goto done;
        received += (long)n;
    }
    ok = EVP_DigestFinal_ex(ctx, hash, &hash_len) > 0 && hash_len == SHA256_DIGEST_LENGTH;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int prepare_signature(const char *filename, long filesize, const unsigned char hash[SHA256_DIGEST_LENGTH], const char *key, unsigned char **sig, size_t *sig_len) {
    Signed_Info signed_info;
    make_signed_info(&signed_info, filename, filesize, hash);
    return eddsa_sign_with_key((unsigned char *)&signed_info, sizeof(signed_info), sig, sig_len, key);
}

static int verify_signature(const char *filename, const File_Info *info, const unsigned char *sig, const char *key) {
    Signed_Info signed_info;
    make_signed_info(&signed_info, filename, info->filesize, info->hash);
    return info->sign_len == ED25519_SIG_LEN &&
           eddsa_verify_with_key((unsigned char *)&signed_info, sizeof(signed_info), sig, ED25519_SIG_LEN, key);
}

void handle_put(int client_sock) {
    char filename[NAME_SIZE] = {0};
    File_Info info;
    unsigned char sign[ED25519_SIG_LEN];

    if (!recv_all(client_sock, filename, sizeof(filename)) || !recv_all(client_sock, &info, sizeof(info))) return;

    const char *safe_name = path_basename(filename);
    if (!valid_filename(safe_name) || info.filesize < 0 || info.sign_len != ED25519_SIG_LEN || !recv_all(client_sock, sign, sizeof(sign))) {
        send_ack(client_sock, "FAIL");
        return;
    }

    if (!ensure_files_dir()) {
        send_ack(client_sock, "FAIL");
        return;
    }

    char save_path[512], tmp_path[520];
    if (!build_file_path(save_path, sizeof(save_path), safe_name)) {
        send_ack(client_sock, "FAIL");
        return;
    }
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", save_path);

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        perror("파일 열기 실패");
        send_ack(client_sock, "FAIL");
        return;
    }

    unsigned char recv_hash[SHA256_DIGEST_LENGTH];
    int ok = recv_file_data(client_sock, fp, info.filesize, recv_hash);
    fclose(fp);

    int hash_ok = ok && memcmp(recv_hash, info.hash, SHA256_DIGEST_LENGTH) == 0;
    int sign_ok = hash_ok && verify_signature(safe_name, &info, sign, CLIENT_PUBLIC_KEY);
    int save_ok = sign_ok && rename(tmp_path, save_path) == 0;

    printf("[업로드 서명 검증]\n");
    printf("파일: %s (%1ld byte)\n", safe_name, info.filesize);
    //printf("파일 크기: %ld byte\n", info.filesize);
    printf("검증 대상: [파일명 + 파일크기 + 파일 전체 SHA-256]\n");
    printf("수신 파일 SHA-256 해시값: ");
    print_hash(recv_hash);
    printf("\n서명 대상 SHA-256 해시값: ");
    print_hash(info.hash);
    printf("\n사용 공개키: %s\n", CLIENT_PUBLIC_KEY);
    printf("수신된 디지털 서명(Ed25519): ");
    print_signature_preview(sign, sizeof(sign));
    printf("\n해시 비교 결과: %s\n", hash_ok ? "일치" : "불일치");
    printf("서명 검증 결과: %s\n", sign_ok ? "성공" : "실패");
    printf("저장 결과: %s\n", save_ok ? "성공" : "실패");

    if (save_ok) {
        send_ack(client_sock, "OK");
    } else {
        remove(tmp_path);
        send_ack(client_sock, "FAIL");
    }
}

void handle_get(int client_sock) {
    char filename[NAME_SIZE] = {0};
    if (!recv_all(client_sock, filename, sizeof(filename))) return;

    const char *safe_name = path_basename(filename);
    File_Info info = { .filesize = -1 };
    if (!valid_filename(safe_name)) {
        send_all(client_sock, &info, sizeof(info));
        return;
    }

    if (!ensure_files_dir()) {
        send_all(client_sock, &info, sizeof(info));
        return;
    }

    char filepath[512];
    if (!build_file_path(filepath, sizeof(filepath), safe_name)) {
        send_all(client_sock, &info, sizeof(info));
        return;
    }
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        send_all(client_sock, &info, sizeof(info));
        printf("서버에 해당 파일이 없습니다: %s\n", safe_name);
        return;
    }

    if (!file_sha256(fp, &info.filesize, info.hash)) {
        fclose(fp);
        send_all(client_sock, &info, sizeof(info));
        return;
    }

    unsigned char *sign = NULL;
    size_t sign_len = 0;
    if (!prepare_signature(safe_name, info.filesize, info.hash, SERVER_PRIVATE_KEY, &sign, &sign_len)) {
        fclose(fp);
        send_all(client_sock, &info, sizeof(info));
        return;
    }
    info.sign_len = (int)sign_len;

    int ok = send_all(client_sock, &info, sizeof(info)) &&
             send_all(client_sock, sign, sign_len) &&
             send_file_data(client_sock, fp, info.filesize);

    printf("[다운로드 서명 생성]\n");
    printf("파일: %s (%1ld byte)\n", safe_name, info.filesize);
    //printf("파일 크기: %ld byte\n", info.filesize);
    printf("서명 대상: [파일명 + 파일크기 + 파일 전체 SHA-256]\n");
    printf("서명 대상 SHA-256 해시값: ");
    print_hash(info.hash);
    printf("\n사용 개인키: %s\n", SERVER_PRIVATE_KEY);
    printf("생성된 디지털 서명(Ed25519): ");
    print_signature_preview(sign, sign_len);
    printf("\n전송 결과: %s\n", ok ? "완료" : "실패");

    free(sign);
    fclose(fp);
}

int main(void) {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int shutdown_server = 0;

    if (!ensure_files_dir()) return 1;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("소켓 생성 실패");
        exit(1);
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("바인드 실패");
        exit(1);
    }

    listen(server_sock, 5);
    printf("클라이언트 접속 대기 중 ...\n");

    while (!shutdown_server) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept 실패");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN] = "알수없음";
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("\n클라이언트 접속: %s:%d\n\n", client_ip, ntohs(client_addr.sin_port));
        fflush(stdout);

        while (1) {
            char command[COMMAND_SIZE] = {0};
            if (!recv_all(client_sock, command, sizeof(command))) {
                printf("클라이언트 연결 종료\n\n");
                break;
            }

            printf("클라이언트 명령: %s\n\n", command);
            fflush(stdout);

            if (strcmp(command, "exit") == 0) {
                printf("클라이언트가 exit 명령을 보냄. 서버 종료\n");
                shutdown_server = 1;
                break;
            }

            if (strcmp(command, "up") == 0) handle_put(client_sock);
            else if (strcmp(command, "down") == 0) handle_get(client_sock);
            else printf("알 수 없는 명령: %s\n", command);
            printf("\n");
        }

        close(client_sock);
    }

    close(server_sock);
    return 0;
}
