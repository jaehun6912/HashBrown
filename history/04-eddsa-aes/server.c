#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#define PORT 10101
#define BUFFER_SIZE 65536
#define NAME_SIZE 256
#define COMMAND_SIZE 16
#define ACK_SIZE 16
#define ED25519_SIG_LEN 64
#define CLIENT_PUBLIC_KEY "client_public.pem"
#define SERVER_PRIVATE_KEY "server_private.pem"
#define DEFAULT_AES_KEY_FILE "aes_key.bin"
#define FILE_DIR "Files"
#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define AES_VALUE_PREVIEW_SIZE 8

typedef struct {
    EVP_CIPHER_CTX *ctx;
} AesGcmContext;

typedef struct {
    long filesize;
    int sign_len;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char iv[AES_GCM_IV_SIZE];
} File_Info;

typedef struct {
    char filename[NAME_SIZE];
    long filesize;
    unsigned char hash[SHA256_DIGEST_LENGTH];
} Signed_Info;

extern int eddsa_sign_with_key(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len, const char *key_path);
extern int eddsa_verify_with_key(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len, const char *key_path);
extern int aes_load_key(const char *key_path, unsigned char key[AES_256_KEY_SIZE]);
extern int aes_generate_iv(unsigned char iv[AES_GCM_IV_SIZE]);
extern int aes_gcm_encrypt_init(AesGcmContext *context, const unsigned char key[AES_256_KEY_SIZE], const unsigned char iv[AES_GCM_IV_SIZE], const void *aad, size_t aad_len);
extern int aes_gcm_decrypt_init(AesGcmContext *context, const unsigned char key[AES_256_KEY_SIZE], const unsigned char iv[AES_GCM_IV_SIZE], const void *aad, size_t aad_len);
extern int aes_gcm_encrypt_update(AesGcmContext *context, const unsigned char *input, int input_len, unsigned char *output, int *output_len);
extern int aes_gcm_decrypt_update(AesGcmContext *context, const unsigned char *input, int input_len, unsigned char *output, int *output_len);
extern int aes_gcm_encrypt_final(AesGcmContext *context, unsigned char *output, int *output_len, unsigned char tag[AES_GCM_TAG_SIZE]);
extern int aes_gcm_decrypt_final(AesGcmContext *context, unsigned char *output, int *output_len, const unsigned char tag[AES_GCM_TAG_SIZE]);
extern void aes_gcm_cleanup(AesGcmContext *context);

static unsigned char aes_key[AES_256_KEY_SIZE];

static const char *aes_key_path(void) {
    const char *path = getenv("AES_KEY_FILE");
    return path && path[0] != '\0' ? path : DEFAULT_AES_KEY_FILE;
}

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
    for (int i = 0; i < AES_VALUE_PREVIEW_SIZE; i++) printf("%02X", hash[i]);
    printf("...");
}

static void print_signature_preview(const unsigned char *sig, size_t sig_len) {
    size_t show_len = sig_len < AES_VALUE_PREVIEW_SIZE
                          ? sig_len
                          : AES_VALUE_PREVIEW_SIZE;
    for (size_t i = 0; i < show_len; i++) printf("%02X", sig[i]);
    if (sig_len > show_len) printf("...");
}

static void capture_preview(unsigned char preview[AES_VALUE_PREVIEW_SIZE],
                            size_t *preview_len,
                            const unsigned char *data,
                            size_t data_len) {
    if (*preview_len >= AES_VALUE_PREVIEW_SIZE) return;
    size_t copy_len = AES_VALUE_PREVIEW_SIZE - *preview_len;
    if (copy_len > data_len) copy_len = data_len;
    memcpy(preview + *preview_len, data, copy_len);
    *preview_len += copy_len;
}

static void print_short_hex(const unsigned char *data, size_t data_len) {
    if (data_len == 0) {
        printf("(없음)");
        return;
    }
    size_t show_len = data_len < AES_VALUE_PREVIEW_SIZE ? data_len : AES_VALUE_PREVIEW_SIZE;
    for (size_t i = 0; i < show_len; i++) printf("%02X", data[i]);
    printf("...");
}

static void print_aes_values(const unsigned char iv[AES_GCM_IV_SIZE],
                             const unsigned char *ciphertext,
                             size_t ciphertext_len,
                             const unsigned char tag[AES_GCM_TAG_SIZE]) {
    printf("AES IV: ");
    print_short_hex(iv, AES_GCM_IV_SIZE);
    printf("\nAES 암호문: ");
    print_short_hex(ciphertext, ciphertext_len);
    printf("\nAES 인증 태그: ");
    print_short_hex(tag, AES_GCM_TAG_SIZE);
    printf("\n\n");
}

static void make_signed_info(Signed_Info *out, const char *filename, long filesize, const unsigned char hash[SHA256_DIGEST_LENGTH]) {
    memset(out, 0, sizeof(*out));
    strncpy(out->filename, filename, NAME_SIZE - 1);
    out->filesize = filesize;
    memcpy(out->hash, hash, SHA256_DIGEST_LENGTH);
}

static int build_sender_signature_input(
    FILE *fp,
    long *filesize,
    unsigned char hash[SHA256_DIGEST_LENGTH],
    unsigned char **signature_input,
    size_t *signature_input_len) {
    unsigned char *input = NULL;
    unsigned int hash_len = 0;
    size_t file_len;
    int ok = 0;

    *signature_input = NULL;
    *signature_input_len = 0;
    if (fseek(fp, 0, SEEK_END) != 0) goto done;
    *filesize = ftell(fp);
    if (*filesize < 0 ||
        (uintmax_t)*filesize >
            (uintmax_t)(SIZE_MAX - SHA256_DIGEST_LENGTH)) {
        goto done;
    }
    file_len = (size_t)*filesize;
    input = malloc(file_len + SHA256_DIGEST_LENGTH);
    if (!input || fseek(fp, 0, SEEK_SET) != 0) goto done;
    if (file_len > 0 && fread(input, 1, file_len, fp) != file_len) goto done;
    if (ferror(fp) ||
        EVP_Digest(input, file_len, hash, &hash_len,
                   EVP_sha256(), NULL) != 1 ||
        hash_len != SHA256_DIGEST_LENGTH) {
        goto done;
    }

    memcpy(input + file_len, hash, SHA256_DIGEST_LENGTH);
    if (fseek(fp, 0, SEEK_SET) != 0) goto done;
    *signature_input = input;
    *signature_input_len = file_len + SHA256_DIGEST_LENGTH;
    input = NULL;
    ok = 1;

done:
    free(input);
    return ok;
}

static int build_receiver_signature_input(
    FILE *fp,
    long filesize,
    const unsigned char transmitted_hash[SHA256_DIGEST_LENGTH],
    unsigned char **signature_input,
    size_t *signature_input_len) {
    unsigned char *input = NULL;
    size_t file_len;

    *signature_input = NULL;
    *signature_input_len = 0;
    if (filesize < 0 ||
        (uintmax_t)filesize >
            (uintmax_t)(SIZE_MAX - SHA256_DIGEST_LENGTH)) {
        return 0;
    }
    file_len = (size_t)filesize;
    input = malloc(file_len + SHA256_DIGEST_LENGTH);
    if (!input || fflush(fp) != 0 || fseek(fp, 0, SEEK_SET) != 0) {
        free(input);
        return 0;
    }
    if ((file_len > 0 && fread(input, 1, file_len, fp) != file_len) ||
        ferror(fp)) {
        free(input);
        return 0;
    }

    memcpy(input + file_len, transmitted_hash, SHA256_DIGEST_LENGTH);
    *signature_input = input;
    *signature_input_len = file_len + SHA256_DIGEST_LENGTH;
    return 1;
}

static int send_encrypted_file_data(int fd,
                                    FILE *fp,
                                    long filesize,
                                    const unsigned char iv[AES_GCM_IV_SIZE],
                                    const Signed_Info *aad) {
    unsigned char plain[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char cipher_preview[AES_VALUE_PREVIEW_SIZE] = {0};
    size_t cipher_preview_len = 0;
    long read_total = 0;
    long encrypted_total = 0;
    int out_len = 0;
    int ok = 0;
    AesGcmContext context = {0};

    if (!aes_gcm_encrypt_init(&context, aes_key, iv, aad, sizeof(*aad))) goto done;

    while (read_total < filesize) {
        size_t wanted = (filesize - read_total < BUFFER_SIZE)
                            ? (size_t)(filesize - read_total)
                            : BUFFER_SIZE;
        size_t n = fread(plain, 1, wanted, fp);
        if (n != wanted ||
            !aes_gcm_encrypt_update(&context, plain, (int)n, encrypted, &out_len)) {
            goto done;
        }
        capture_preview(cipher_preview, &cipher_preview_len, encrypted, (size_t)out_len);
        if (!send_all(fd, encrypted, (size_t)out_len)) goto done;
        read_total += (long)n;
        encrypted_total += out_len;
    }

    if (!aes_gcm_encrypt_final(&context, encrypted, &out_len, tag)) {
        goto done;
    }
    capture_preview(cipher_preview, &cipher_preview_len, encrypted, (size_t)out_len);
    print_aes_values(iv, cipher_preview, cipher_preview_len, tag);
    if (!send_all(fd, encrypted, (size_t)out_len)) goto done;
    encrypted_total += out_len;

    ok = encrypted_total == filesize && send_all(fd, tag, sizeof(tag));

done:
    aes_gcm_cleanup(&context);
    OPENSSL_cleanse(plain, sizeof(plain));
    return ok;
}

static int recv_encrypted_file_data(int fd,
                                    FILE *fp,
                                    long filesize,
                                    const unsigned char iv[AES_GCM_IV_SIZE],
                                    const Signed_Info *aad) {
    unsigned char encrypted[BUFFER_SIZE];
    unsigned char plain[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char cipher_preview[AES_VALUE_PREVIEW_SIZE] = {0};
    size_t cipher_preview_len = 0;
    long received = 0;
    long plain_total = 0;
    int out_len = 0;
    int ok = 0;
    AesGcmContext context = {0};

    if (!aes_gcm_decrypt_init(&context, aes_key, iv, aad, sizeof(*aad))) {
        goto done;
    }
    while (received < filesize) {
        size_t n = (filesize - received < BUFFER_SIZE) ? (size_t)(filesize - received) : BUFFER_SIZE;
        if (!recv_all(fd, encrypted, n)) goto done;
        capture_preview(cipher_preview, &cipher_preview_len, encrypted, n);
        if (!aes_gcm_decrypt_update(&context, encrypted, (int)n, plain, &out_len) ||
            fwrite(plain, 1, (size_t)out_len, fp) != (size_t)out_len) {
            goto done;
        }
        received += (long)n;
        plain_total += out_len;
    }

    if (!recv_all(fd, tag, sizeof(tag))) goto done;
    print_aes_values(iv, cipher_preview, cipher_preview_len, tag);
    if (!aes_gcm_decrypt_final(&context, plain, &out_len, tag) ||
        fwrite(plain, 1, (size_t)out_len, fp) != (size_t)out_len) {
        goto done;
    }
    plain_total += out_len;
    ok = plain_total == filesize;

done:
    aes_gcm_cleanup(&context);
    OPENSSL_cleanse(plain, sizeof(plain));
    return ok;
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

    FILE *fp = fopen(tmp_path, "w+b");
    if (!fp) {
        perror("파일 열기 실패");
        send_ack(client_sock, "FAIL");
        return;
    }

    Signed_Info signed_info;
    make_signed_info(&signed_info, safe_name, info.filesize, info.hash);
    int ok = recv_encrypted_file_data(client_sock, fp, info.filesize,
                                      info.iv, &signed_info);
    unsigned char *verify_input = NULL;
    size_t verify_input_len = 0;
    int sign_ok = ok &&
                  build_receiver_signature_input(fp, info.filesize, info.hash,
                                                 &verify_input,
                                                 &verify_input_len) &&
                  eddsa_verify_with_key(verify_input, verify_input_len,
                                        sign, ED25519_SIG_LEN,
                                        CLIENT_PUBLIC_KEY);
    free(verify_input);
    fclose(fp);

    int save_ok = sign_ok && rename(tmp_path, save_path) == 0;

    printf("[업로드 서명 검증]\n");
    printf("파일: %s (%1ld byte)\n", safe_name, info.filesize);
    //printf("파일 크기: %ld byte\n", info.filesize);
    printf("검증 대상: [수신 파일 전체 내용 + 전달받은 파일 SHA-256]\n");
    printf("전달받은 파일 SHA-256: ");
    print_hash(info.hash);
    printf("\nAES-256-GCM 복호화/인증: %s", ok ? "성공" : "실패");
    printf("\n사용 공개키: %s\n", CLIENT_PUBLIC_KEY);
    printf("수신된 디지털 서명(Ed25519): ");
    print_signature_preview(sign, sizeof(sign));
    printf("\n통합 서명 검증 결과: %s\n", sign_ok ? "성공" : "실패");
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

    unsigned char *signature_input = NULL;
    size_t signature_input_len = 0;
    if (!build_sender_signature_input(fp, &info.filesize, info.hash,
                                      &signature_input,
                                      &signature_input_len)) {
        fclose(fp);
        send_all(client_sock, &info, sizeof(info));
        return;
    }

    unsigned char *sign = NULL;
    size_t sign_len = 0;
    if (!eddsa_sign_with_key(signature_input, signature_input_len,
                             &sign, &sign_len, SERVER_PRIVATE_KEY)) {
        free(signature_input);
        fclose(fp);
        send_all(client_sock, &info, sizeof(info));
        return;
    }
    free(signature_input);
    info.sign_len = (int)sign_len;
    if (!aes_generate_iv(info.iv)) {
        free(sign);
        fclose(fp);
        info.filesize = -1;
        send_all(client_sock, &info, sizeof(info));
        return;
    }

    Signed_Info signed_info;
    make_signed_info(&signed_info, safe_name, info.filesize, info.hash);

    int ok = send_all(client_sock, &info, sizeof(info)) &&
             send_all(client_sock, sign, sign_len) &&
             send_encrypted_file_data(client_sock, fp, info.filesize,
                                      info.iv, &signed_info);

    printf("[다운로드 서명 생성]\n");
    printf("파일: %s (%1ld byte)\n", safe_name, info.filesize);
    //printf("파일 크기: %ld byte\n", info.filesize);
    printf("서명 대상: [파일 전체 내용 + 파일 SHA-256]\n");
    printf("서명 대상 SHA-256 해시값: ");
    print_hash(info.hash);
    printf("\n사용 개인키: %s\n", SERVER_PRIVATE_KEY);
    printf("생성된 디지털 서명(Ed25519): ");
    print_signature_preview(sign, sign_len);
    printf("\n파일 데이터 암호화: AES-256-GCM");
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

    const char *key_path = aes_key_path();
    if (!aes_load_key(key_path, aes_key)) {
        printf("AES 키 로드 실패: %s (정확히 32바이트여야 합니다)\n", key_path);
        return 1;
    }

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
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    return 0;
}
