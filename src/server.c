#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
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
#define CLIENT_KEY_DIR "clients"
#define SERVER_PRIVATE_KEY "server_private.pem"
#define FILE_DIR "Files"
#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define AES_VALUE_PREVIEW_SIZE 8
#define HEX_PREVIEW_BYTES 4   // 해시·서명·키 등 긴 값은 앞 4바이트(16진수 8자리)만 표시
#define X25519_KEY_SIZE 32
#define HANDSHAKE_LABEL_SIZE 16
#define PEER_NAME_SIZE 32
#define PEER_LABEL_SIZE (NAME_SIZE + PEER_NAME_SIZE + 2)
#define LOG_BUFFER_SIZE 16384
#define MAX_LIST_ENTRIES 10000

typedef struct {
    EVP_CIPHER_CTX *ctx;
} AesGcmContext;

// 아래 구조체는 바이트 그대로 전송/서명되므로 32/64비트 환경(PC, 라즈베리파이)에서
// 크기가 같도록 고정 크기 정수(int64_t, int32_t)를 사용함
typedef struct {
    int64_t filesize;
    int32_t sign_len;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char iv[AES_GCM_IV_SIZE];
} File_Info;

typedef struct {
    char filename[NAME_SIZE];
    int64_t filesize;
    unsigned char hash[SHA256_DIGEST_LENGTH];
} Signed_Info;

// X25519 키 교환 시 Ed25519로 서명하는 대상 (label로 서버/클라이언트 서명을 구분)
typedef struct {
    char label[HANDSHAKE_LABEL_SIZE];
    unsigned char client_pub[X25519_KEY_SIZE];
    unsigned char server_pub[X25519_KEY_SIZE];
} Handshake_Info;

// list 명령: 헤더(항목 수, IV)는 평문으로, 항목들은 AES-GCM으로 암호화해서 전송
typedef struct {
    int32_t count;
    unsigned char iv[AES_GCM_IV_SIZE];
} List_Info;

typedef struct {
    char filename[NAME_SIZE];
    int64_t filesize;
} List_Entry;

_Static_assert(sizeof(File_Info) == 56, "File_Info 크기는 모든 플랫폼에서 같아야 함");
_Static_assert(sizeof(Signed_Info) == 296, "Signed_Info 크기는 모든 플랫폼에서 같아야 함");
_Static_assert(sizeof(Handshake_Info) == 80, "Handshake_Info 크기는 모든 플랫폼에서 같아야 함");
_Static_assert(sizeof(List_Info) == 16, "List_Info 크기는 모든 플랫폼에서 같아야 함");
_Static_assert(sizeof(List_Entry) == 264, "List_Entry 크기는 모든 플랫폼에서 같아야 함");

extern int eddsa_sign_with_key(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len, const char *key_path);
extern int eddsa_verify_with_key(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len, const char *key_path);
extern EVP_PKEY *x25519_generate_key(unsigned char pub[X25519_KEY_SIZE]);
extern int x25519_derive_session_key(EVP_PKEY *own_key, const unsigned char peer_pub[X25519_KEY_SIZE], const unsigned char *salt, size_t salt_len, unsigned char session_key[AES_256_KEY_SIZE]);
extern int aes_generate_iv(unsigned char iv[AES_GCM_IV_SIZE]);
extern int aes_gcm_encrypt_init(AesGcmContext *context, const unsigned char key[AES_256_KEY_SIZE], const unsigned char iv[AES_GCM_IV_SIZE], const void *aad, size_t aad_len);
extern int aes_gcm_decrypt_init(AesGcmContext *context, const unsigned char key[AES_256_KEY_SIZE], const unsigned char iv[AES_GCM_IV_SIZE], const void *aad, size_t aad_len);
extern int aes_gcm_encrypt_update(AesGcmContext *context, const unsigned char *input, int input_len, unsigned char *output, int *output_len);
extern int aes_gcm_decrypt_update(AesGcmContext *context, const unsigned char *input, int input_len, unsigned char *output, int *output_len);
extern int aes_gcm_encrypt_final(AesGcmContext *context, unsigned char *output, int *output_len, unsigned char tag[AES_GCM_TAG_SIZE]);
extern int aes_gcm_decrypt_final(AesGcmContext *context, unsigned char *output, int *output_len, const unsigned char tag[AES_GCM_TAG_SIZE]);
extern void aes_gcm_cleanup(AesGcmContext *context);

// 접속마다 X25519로 유도한 세션키. fork()된 프로세스마다 따로 가지므로 클라이언트끼리 공유되지 않음
static unsigned char aes_key[AES_256_KEY_SIZE];
static char peer_name[PEER_NAME_SIZE] = "알수없음";
// 키 교환 서명이 일치한 등록 클라이언트 (clients/<이름>.pem). fork()된 프로세스마다 따로 가짐
static char client_name[NAME_SIZE] = "";
static char client_key_path[512] = "";
// 인증 이후 로그에 쓰는 "이름 IP:포트"
static char peer_label[PEER_LABEL_SIZE] = "";

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

// 해시·서명·키·암호문 등 긴 값은 앞 HEX_PREVIEW_BYTES 바이트만 16진수로 표시하고 뒤는 ... 처리
static void print_short_hex(const unsigned char *data, size_t data_len) {
    if (data_len == 0) {
        printf("(없음)");
        return;
    }
    size_t show_len = data_len < HEX_PREVIEW_BYTES ? data_len : HEX_PREVIEW_BYTES;
    for (size_t i = 0; i < show_len; i++) printf("%02X", data[i]);
    if (data_len > show_len) printf("...");
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

// 화면 표시용 AES-GCM 값: 암호문 앞부분과 인증 태그 (전송 함수가 채우고, 결과 출력 때 한 줄로 표시)
typedef struct {
    unsigned char cipher[AES_VALUE_PREVIEW_SIZE];
    size_t cipher_len;
    unsigned char tag[AES_GCM_TAG_SIZE];
    int has_tag;
} Aes_Preview;

static void print_aes_preview(const unsigned char iv[AES_GCM_IV_SIZE], const Aes_Preview *pv) {
    printf("IV ");
    print_short_hex(iv, AES_GCM_IV_SIZE);
    printf(", 암호문 ");
    print_short_hex(pv->cipher, pv->cipher_len);
    printf(", 태그 ");
    if (pv->has_tag) print_short_hex(pv->tag, AES_GCM_TAG_SIZE);
    else printf("(없음)");
}

static void make_signed_info(Signed_Info *out, const char *filename, int64_t filesize, const unsigned char hash[SHA256_DIGEST_LENGTH]) {
    memset(out, 0, sizeof(*out));
    // 최대 NAME_SIZE-1 글자만 복사 (나머지는 위 memset 으로 0 이므로 항상 문자열 끝이 보장됨)
    memcpy(out->filename, filename, strnlen(filename, NAME_SIZE - 1));
    out->filesize = filesize;
    memcpy(out->hash, hash, SHA256_DIGEST_LENGTH);
}

static void make_handshake_info(Handshake_Info *out, const char *label,
                                const unsigned char client_pub[X25519_KEY_SIZE],
                                const unsigned char server_pub[X25519_KEY_SIZE]) {
    memset(out, 0, sizeof(*out));
    strncpy(out->label, label, HANDSHAKE_LABEL_SIZE - 1);
    memcpy(out->client_pub, client_pub, X25519_KEY_SIZE);
    memcpy(out->server_pub, server_pub, X25519_KEY_SIZE);
}

// 세션키 자체는 출력하지 않고 SHA-256 지문만 보여줌 (양쪽 지문이 같으면 같은 키)
static void print_key_fingerprint(const unsigned char key[AES_256_KEY_SIZE]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len = 0;
    if (EVP_Digest(key, AES_256_KEY_SIZE, digest, &digest_len, EVP_sha256(), NULL) <= 0) {
        printf("(계산 실패)");
        return;
    }
    print_short_hex(digest, digest_len);
}

static int file_sha256(FILE *fp, int64_t *filesize, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    unsigned char buf[BUFFER_SIZE];
    unsigned int hash_len = 0;
    off_t size;
    int ok = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0) goto done;
    if (fseeko(fp, 0, SEEK_END) != 0) goto done;
    size = ftello(fp);
    if (size < 0 || fseeko(fp, 0, SEEK_SET) != 0) goto done;
    *filesize = (int64_t)size;

    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) <= 0) goto done;
    }
    if (ferror(fp)) goto done;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) <= 0 || hash_len != SHA256_DIGEST_LENGTH) goto done;
    ok = fseeko(fp, 0, SEEK_SET) == 0;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int send_encrypted_file_data(int fd,
                                    FILE *fp,
                                    int64_t filesize,
                                    const unsigned char iv[AES_GCM_IV_SIZE],
                                    const Signed_Info *aad,
                                    Aes_Preview *pv) {
    unsigned char plain[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int64_t read_total = 0;
    int64_t encrypted_total = 0;
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
        capture_preview(pv->cipher, &pv->cipher_len, encrypted, (size_t)out_len);
        if (!send_all(fd, encrypted, (size_t)out_len)) goto done;
        read_total += (int64_t)n;
        encrypted_total += out_len;
    }

    if (!aes_gcm_encrypt_final(&context, encrypted, &out_len, pv->tag)) {
        goto done;
    }
    pv->has_tag = 1;
    capture_preview(pv->cipher, &pv->cipher_len, encrypted, (size_t)out_len);
    if (!send_all(fd, encrypted, (size_t)out_len)) goto done;
    encrypted_total += out_len;

    ok = encrypted_total == filesize && send_all(fd, pv->tag, AES_GCM_TAG_SIZE);

done:
    aes_gcm_cleanup(&context);
    OPENSSL_cleanse(plain, sizeof(plain));
    return ok;
}

static int recv_encrypted_file_data(int fd,
                                    FILE *fp,
                                    int64_t filesize,
                                    const unsigned char iv[AES_GCM_IV_SIZE],
                                    const Signed_Info *aad,
                                    unsigned char hash[SHA256_DIGEST_LENGTH],
                                    Aes_Preview *pv) {
    unsigned char encrypted[BUFFER_SIZE];
    unsigned char plain[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned int hash_len = 0;
    int64_t received = 0;
    int64_t plain_total = 0;
    int out_len = 0;
    int ok = 0;
    AesGcmContext context = {0};
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    memset(hash, 0, SHA256_DIGEST_LENGTH);
    if (!hash_ctx) return 0;

    if (!aes_gcm_decrypt_init(&context, aes_key, iv, aad, sizeof(*aad)) ||
        EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL) <= 0) {
        goto done;
    }
    while (received < filesize) {
        size_t n = (filesize - received < BUFFER_SIZE) ? (size_t)(filesize - received) : BUFFER_SIZE;
        if (!recv_all(fd, encrypted, n)) goto done;
        capture_preview(pv->cipher, &pv->cipher_len, encrypted, n);
        if (!aes_gcm_decrypt_update(&context, encrypted, (int)n, plain, &out_len) ||
            fwrite(plain, 1, (size_t)out_len, fp) != (size_t)out_len ||
            EVP_DigestUpdate(hash_ctx, plain, (size_t)out_len) <= 0) {
            goto done;
        }
        received += (int64_t)n;
        plain_total += out_len;
    }

    if (!recv_all(fd, pv->tag, AES_GCM_TAG_SIZE)) goto done;
    pv->has_tag = 1;
    if (!aes_gcm_decrypt_final(&context, plain, &out_len, pv->tag) ||
        fwrite(plain, 1, (size_t)out_len, fp) != (size_t)out_len ||
        EVP_DigestUpdate(hash_ctx, plain, (size_t)out_len) <= 0) {
        goto done;
    }
    plain_total += out_len;
    ok = plain_total == filesize &&
         EVP_DigestFinal_ex(hash_ctx, hash, &hash_len) > 0 &&
         hash_len == SHA256_DIGEST_LENGTH;

done:
    aes_gcm_cleanup(&context);
    EVP_MD_CTX_free(hash_ctx);
    OPENSSL_cleanse(plain, sizeof(plain));
    return ok;
}

static int prepare_signature(const char *filename, int64_t filesize,const unsigned char hash[SHA256_DIGEST_LENGTH], const char *key, unsigned char **sig, size_t *sig_len) {
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
    filename[NAME_SIZE - 1] = '\0';

    const char *safe_name = path_basename(filename);
    if (!valid_filename(safe_name) || info.filesize < 0|| info.sign_len != ED25519_SIG_LEN || !recv_all(client_sock, sign, sizeof(sign))) {
        printf("[%s] 업로드 요청 거부: 잘못된 파일 정보 (%s)\n", peer_label, safe_name);
        send_ack(client_sock, "FAIL");
        return;
    }

    if (!ensure_files_dir()) {
        send_ack(client_sock, "FAIL");
        return;
    }

    char save_path[512], tmp_path[540];
    if (!build_file_path(save_path, sizeof(save_path), safe_name)) {
        send_ack(client_sock, "FAIL");
        return;
    }
    // 여러 클라이언트가 같은 파일명을 동시에 올려도 임시 파일이 겹치지 않도록 PID를 붙임
    snprintf(tmp_path, sizeof(tmp_path), "%s.%d.tmp", save_path, (int)getpid());

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        perror("파일 열기 실패");
        send_ack(client_sock, "FAIL");
        return;
    }

    Signed_Info signed_info;
    make_signed_info(&signed_info, safe_name, info.filesize, info.hash);
    unsigned char recv_hash[SHA256_DIGEST_LENGTH];
    Aes_Preview pv = {0};
    int ok = recv_encrypted_file_data(client_sock, fp, info.filesize,
                                      info.iv, &signed_info, recv_hash, &pv);
    fclose(fp);

    int hash_ok = ok && memcmp(recv_hash, info.hash, SHA256_DIGEST_LENGTH) == 0;
    // 업로드 파일 서명은 키 교환에서 인증된 바로 그 클라이언트의 공개키로 검증
    int sign_ok = hash_ok && verify_signature(safe_name, &info, sign, client_key_path);
    int save_ok = sign_ok && rename(tmp_path, save_path) == 0;

    printf("[%s] 업로드 수신: %s (%lld byte)\n", peer_label, safe_name, (long long)info.filesize);
    printf("  AES-256-GCM 복호화/인증: %s (", ok ? "성공" : "실패");
    print_aes_preview(info.iv, &pv);
    printf(")\n");
    printf("  해시 비교 결과: %s (", hash_ok ? "일치" : "불일치");
    if (!ok) {
        printf("복호화/인증 실패로 비교 불가");
    } else if (hash_ok) {
        printf("SHA-256 ");
        print_short_hex(info.hash, SHA256_DIGEST_LENGTH);
    } else {
        printf("수신 ");
        print_short_hex(recv_hash, SHA256_DIGEST_LENGTH);
        printf(" / 서명 대상 ");
        print_short_hex(info.hash, SHA256_DIGEST_LENGTH);
    }
    printf(")\n");
    printf("  서명 검증 결과: %s (Ed25519 ", sign_ok ? "성공" : "실패");
    print_short_hex(sign, sizeof(sign));
    printf(", %s)\n", client_key_path);
    printf("  저장 결과: %s\n", save_ok ? "성공" : "실패 (저장하지 않음)");

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
    filename[NAME_SIZE - 1] = '\0';

    const char *safe_name = path_basename(filename);
    File_Info info = { .filesize = -1 };
    if (!valid_filename(safe_name)) {
        printf("[%s] 다운로드 요청 거부: 잘못된 파일명 (%s)\n", peer_label, safe_name);
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
        printf("[%s] 다운로드 요청: %s -> 서버에 해당 파일이 없습니다\n", peer_label, safe_name);
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
    info.sign_len = (int32_t)sign_len;
    if (!aes_generate_iv(info.iv)) {
        free(sign);
        fclose(fp);
        info.filesize = -1;
        send_all(client_sock, &info, sizeof(info));
        return;
    }

    Signed_Info signed_info;
    make_signed_info(&signed_info, safe_name, info.filesize, info.hash);

    Aes_Preview pv = {0};
    int ok = send_all(client_sock, &info, sizeof(info)) &&
             send_all(client_sock, sign, sign_len) &&
             send_encrypted_file_data(client_sock, fp, info.filesize,
                                      info.iv, &signed_info, &pv);

    printf("[%s] 다운로드 송신: %s (%lld byte)\n", peer_label, safe_name, (long long)info.filesize);
    printf("  SHA-256 ");
    print_short_hex(info.hash, SHA256_DIGEST_LENGTH);
    printf(" / Ed25519 서명 ");
    print_short_hex(sign, sign_len);
    printf(" (%s)\n", SERVER_PRIVATE_KEY);
    printf("  AES-256-GCM 암호화: ");
    print_aes_preview(info.iv, &pv);
    printf("\n");
    printf("  전송 결과: %s\n", ok ? "완료" : "실패");

    free(sign);
    fclose(fp);
}

// 업로드 중인 임시 파일(파일명.PID.tmp)은 목록에서 제외
static int is_transfer_temp_file(const char *name) {
    size_t len = strlen(name);
    if (len < 6 || strcmp(name + len - 4, ".tmp") != 0) return 0;
    size_t end = len - 4, i = end;
    while (i > 0 && isdigit((unsigned char)name[i - 1])) i--;
    return i < end && i > 0 && name[i - 1] == '.';
}

static int compare_list_entry(const void *a, const void *b) {
    return strcmp(((const List_Entry *)a)->filename, ((const List_Entry *)b)->filename);
}

// Files 디렉토리의 일반 파일 목록을 이름순으로 만듦
static int collect_file_list(List_Entry **out, int32_t *count) {
    DIR *dir;
    struct dirent *ent;
    List_Entry *list = NULL;
    int32_t n = 0, cap = 0;

    *out = NULL;
    *count = 0;
    if (!ensure_files_dir() || !(dir = opendir(FILE_DIR))) return 0;

    while ((ent = readdir(dir)) != NULL && n < MAX_LIST_ENTRIES) {
        char path[512];
        struct stat st;
        size_t name_len = strlen(ent->d_name);
        if (!valid_filename(ent->d_name) || is_transfer_temp_file(ent->d_name) ||
            name_len >= NAME_SIZE ||
            !build_file_path(path, sizeof(path), ent->d_name) ||
            stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        if (n == cap) {
            int32_t new_cap = cap ? cap * 2 : 16;
            List_Entry *grown = realloc(list, (size_t)new_cap * sizeof(*list));
            if (!grown) {
                free(list);
                closedir(dir);
                return 0;
            }
            list = grown;
            cap = new_cap;
        }
        memset(&list[n], 0, sizeof(list[n]));
        memcpy(list[n].filename, ent->d_name, name_len + 1);  // 길이는 위에서 NAME_SIZE 미만으로 확인함
        list[n].filesize = (int64_t)st.st_size;
        n++;
    }
    closedir(dir);

    if (n > 1) qsort(list, (size_t)n, sizeof(*list), compare_list_entry);
    *out = list;
    *count = n;
    return 1;
}

void handle_list(int client_sock) {
    List_Entry *list = NULL;
    List_Info info = { .count = -1 };
    unsigned char encrypted[sizeof(List_Entry) + EVP_MAX_BLOCK_LENGTH];
    Aes_Preview pv = {0};
    int out_len = 0;
    int ok = 0;
    AesGcmContext context = {0};

    if (!collect_file_list(&list, &info.count) || !aes_generate_iv(info.iv)) {
        info.count = -1;
        send_all(client_sock, &info, sizeof(info));
        printf("[%s] 파일 목록 송신: 전송 결과: 실패 (목록 조회 오류)\n", peer_label);
        free(list);
        return;
    }

    // 헤더(항목 수, IV)를 AAD로 넣어 항목 수가 조작되면 GCM 태그 검증에서 걸리게 함
    if (!send_all(client_sock, &info, sizeof(info)) ||
        !aes_gcm_encrypt_init(&context, aes_key, info.iv, &info, sizeof(info))) {
        goto done;
    }
    for (int32_t i = 0; i < info.count; i++) {
        if (!aes_gcm_encrypt_update(&context, (const unsigned char *)&list[i], (int)sizeof(List_Entry), encrypted, &out_len)) goto done;
        capture_preview(pv.cipher, &pv.cipher_len, encrypted, (size_t)out_len);
        if (!send_all(client_sock, encrypted, (size_t)out_len)) goto done;
    }
    // GCM은 스트림 방식이라 final 출력은 0바이트이고 인증 태그만 생성됨
    if (!aes_gcm_encrypt_final(&context, encrypted, &out_len, pv.tag) || out_len != 0) goto done;
    pv.has_tag = 1;
    ok = send_all(client_sock, pv.tag, AES_GCM_TAG_SIZE);

done:
    aes_gcm_cleanup(&context);
    printf("[%s] 파일 목록 송신: %d개, 전송 결과: %s\n", peer_label, (int)info.count, ok ? "완료" : "실패");
    printf("  AES-256-GCM 암호화: ");
    print_aes_preview(info.iv, &pv);
    printf("\n");
    free(list);
}

static int is_pem_file(const char *name) {
    size_t len = strlen(name);
    return len > 4 && strcmp(name + len - 4, ".pem") == 0;
}

// clients/ 폴더에 등록된 공개키로 클라이언트 서명을 차례대로 검증해서,
// 서명이 맞는 키를 이 클라이언트의 신원으로 정함 (등록 키가 없거나 모두 불일치하면 0)
static int identify_client(const Handshake_Info *hs, const unsigned char sig[ED25519_SIG_LEN]) {
    DIR *dir = opendir(CLIENT_KEY_DIR);
    struct dirent *ent;
    int found = 0;

    if (!dir) return 0;
    while (!found && (ent = readdir(dir)) != NULL) {
        char path[512];
        size_t len = strlen(ent->d_name);
        if (!is_pem_file(ent->d_name) ||
            snprintf(path, sizeof(path), "%s/%s", CLIENT_KEY_DIR, ent->d_name) >= (int)sizeof(path)) {
            continue;
        }
        if (eddsa_verify_with_key((const unsigned char *)hs, sizeof(*hs), sig, ED25519_SIG_LEN, path)) {
            memcpy(client_key_path, path, strlen(path) + 1);
            memcpy(client_name, ent->d_name, len - 4);
            client_name[len - 4] = '\0';
            found = 1;
        }
    }
    closedir(dir);
    return found;
}

// 서버 시작 시 등록된 클라이언트 목록 표시 (등록/삭제는 서버 재시작 없이 다음 접속부터 반영됨)
static void print_registered_clients(void) {
    DIR *dir;
    struct dirent *ent;
    int n = 0;

    if (mkdir(CLIENT_KEY_DIR, 0755) < 0 && errno != EEXIST) {
        printf("%s 디렉토리 생성 실패: %s\n", CLIENT_KEY_DIR, strerror(errno));
        return;
    }
    printf("등록된 클라이언트 공개키 (%s/): ", CLIENT_KEY_DIR);
    if ((dir = opendir(CLIENT_KEY_DIR)) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (!is_pem_file(ent->d_name)) continue;
            printf("%.*s ", (int)(strlen(ent->d_name) - 4), ent->d_name);
            n++;
        }
        closedir(dir);
    }
    if (n == 0) printf("없음 -> %s/<클라이언트이름>.pem 으로 공개키를 등록하세요", CLIENT_KEY_DIR);
    else printf("(%d개)", n);
    printf("\n");
}

/*
 * X25519 키 교환 (Ed25519 서명으로 상호 인증)
 *   C -> S : 클라이언트 임시 공개키
 *   S -> C : 서버 임시 공개키 + 서버 서명(server_private.pem)
 *   C -> S : 클라이언트 서명(각 클라이언트 자신의 client_private.pem)
 *   서버   : clients 폴더의 .pem 공개키 중 서명이 맞는 키로 어느 클라이언트인지 식별
 *   S -> C : OK / FAIL
 *   양쪽   : X25519 공유값 -> HKDF-SHA256 -> 이번 접속 전용 AES-256 세션키
 */
static int server_handshake(int fd) {
    unsigned char client_pub[X25519_KEY_SIZE] = {0};
    unsigned char server_pub[X25519_KEY_SIZE] = {0};
    unsigned char client_sign[ED25519_SIG_LEN] = {0};
    unsigned char salt[X25519_KEY_SIZE * 2];
    unsigned char *server_sign = NULL;
    size_t server_sign_len = 0;
    int client_sign_received = 0;
    int client_sign_ok = 0;
    int ok = 0;
    Handshake_Info hs;
    EVP_PKEY *server_key = NULL;

    if (!recv_all(fd, client_pub, sizeof(client_pub))) return 0;

    server_key = x25519_generate_key(server_pub);
    if (!server_key) goto done;

    make_handshake_info(&hs, "X25519-SERVER", client_pub, server_pub);
    if (!eddsa_sign_with_key((unsigned char *)&hs, sizeof(hs), &server_sign, &server_sign_len, SERVER_PRIVATE_KEY) ||
        server_sign_len != ED25519_SIG_LEN) {
        goto done;
    }
    if (!send_all(fd, server_pub, sizeof(server_pub)) ||
        !send_all(fd, server_sign, server_sign_len) ||
        !recv_all(fd, client_sign, sizeof(client_sign))) {
        goto done;
    }
    client_sign_received = 1;

    make_handshake_info(&hs, "X25519-CLIENT", client_pub, server_pub);
    client_sign_ok = identify_client(&hs, client_sign);

    memcpy(salt, client_pub, X25519_KEY_SIZE);
    memcpy(salt + X25519_KEY_SIZE, server_pub, X25519_KEY_SIZE);
    ok = client_sign_ok && x25519_derive_session_key(server_key, client_pub, salt, sizeof(salt), aes_key);
    send_ack(fd, ok ? "OK" : "FAIL");

done:
    printf("\n[X25519 키 교환] %s (PID %d)\n", peer_name, (int)getpid());
    printf("  임시 공개키: 클라이언트 ");
    print_short_hex(client_pub, sizeof(client_pub));
    printf(" / 서버 ");
    print_short_hex(server_pub, sizeof(server_pub));
    printf("\n  서버 서명 생성(Ed25519): ");
    if (server_sign) print_short_hex(server_sign, server_sign_len);
    else printf("실패");
    printf(" (%s)\n", SERVER_PRIVATE_KEY);
    printf("  클라이언트 서명 검증(Ed25519): ");
    if (!client_sign_received) printf("수신 안 됨 (클라이언트가 키 교환을 중단함)\n");
    else if (client_sign_ok) printf("성공 -> 인증된 클라이언트: %s (%s)\n", client_name, client_key_path);
    else printf("실패 -> 등록된 클라이언트 공개키(%s/*.pem) 중 서명이 일치하는 키 없음\n", CLIENT_KEY_DIR);
    if (client_sign_ok) {
        printf("  세션키 유도(X25519 + HKDF-SHA256): %s", ok ? "성공" : "실패");
        if (ok) {
            printf(", 세션키 지문(SHA-256): ");
            print_key_fingerprint(aes_key);
        }
        printf("\n");
    }

    free(server_sign);
    EVP_PKEY_free(server_key);
    return ok;
}

// fork()된 자식 프로세스에서 클라이언트 한 명을 담당
static void handle_client(int client_sock) {
    if (!server_handshake(client_sock)) {
        printf("[%s] 키 교환 실패. 연결 종료\n", peer_name);
        return;
    }
    snprintf(peer_label, sizeof(peer_label), "%s %s", client_name, peer_name);
    fflush(stdout);

    while (1) {
        char command[COMMAND_SIZE] = {0};
        if (!recv_all(client_sock, command, sizeof(command))) {
            printf("\n[%s] 클라이언트 연결 종료\n", peer_label);
            break;
        }
        command[COMMAND_SIZE - 1] = '\0';

        // 명령 하나의 출력은 빈 줄 하나로 구분 (각 블록 첫 줄에 [클라이언트 IP:포트] 표시)
        printf("\n");
        if (strcmp(command, "exit") == 0) {
            printf("[%s] 클라이언트가 exit 명령을 보냄. 해당 클라이언트 세션만 종료\n", peer_label);
            break;
        }

        if (strcmp(command, "up") == 0) handle_put(client_sock);
        else if (strcmp(command, "down") == 0) handle_get(client_sock);
        else if (strcmp(command, "list") == 0) handle_list(client_sock);
        else printf("[%s] 알 수 없는 명령: %s\n", peer_label, command);
        // 명령 하나의 출력을 한 번에 내보내서 다른 클라이언트 출력과 섞이지 않게 함
        fflush(stdout);
    }
}

int main(void) {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    if (!ensure_files_dir()) return 1;
    print_registered_clients();

    // 종료된 자식 프로세스를 커널이 자동으로 회수하도록 함 (좀비 프로세스 방지)
    signal(SIGCHLD, SIG_IGN);

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
    printf("클라이언트 접속 대기 중 ... (서버 종료: Ctrl+C)\n");
    fflush(stdout);

    while (1) {
        client_len = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno != EINTR) perror("accept 실패");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN] = "알수없음";
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        snprintf(peer_name, sizeof(peer_name), "%s:%d", client_ip, ntohs(client_addr.sin_port));
        printf("\n클라이언트 접속: %s\n", peer_name);
        // fork() 전에 버퍼를 비워야 자식 프로세스에서 같은 내용이 중복 출력되지 않음
        fflush(stdout);

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork 실패");
            close(client_sock);
            continue;
        }

        if (pid == 0) {
            // 자식 프로세스: 이 클라이언트 하나만 담당
            static char log_buf[LOG_BUFFER_SIZE];
            close(server_sock);
            setvbuf(stdout, log_buf, _IOFBF, sizeof(log_buf));
            handle_client(client_sock);
            fflush(stdout);
            close(client_sock);
            OPENSSL_cleanse(aes_key, sizeof(aes_key));
            exit(0);
        }

        // 부모 프로세스: 소켓은 자식에게 넘기고 바로 다음 접속을 기다림
        close(client_sock);
    }

    close(server_sock);
    return 0;
}
