#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#define BUFFER_SIZE 65536
#define NAME_SIZE 256
#define COMMAND_SIZE 16
#define ACK_SIZE 16
#define ED25519_SIG_LEN 64
#define CLIENT_PRIVATE_KEY "client_private.pem"
#define SERVER_PUBLIC_KEY "server_public.pem"
#define FILE_DIR "Files"
#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define AES_VALUE_PREVIEW_SIZE 8
#define HEX_PREVIEW_BYTES 4   // 해시·서명·키 등 긴 값은 앞 4바이트(16진수 8자리)만 표시
#define X25519_KEY_SIZE 32
#define HANDSHAKE_LABEL_SIZE 16
#define MAX_LIST_ENTRIES 10000

typedef enum {
    CMD_INVALID,
    CMD_UP,
    CMD_DOWN,
    CMD_SERVER_LIST,
    CMD_CLIENT_LIST,
    CMD_EXIT
} Command;

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

// 서버 파일 목록: 헤더(항목 수, IV)는 평문으로, 항목들은 AES-GCM으로 암호화되어 수신됨
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

static int sock;
// 서버 접속 시 X25519로 유도한 이번 접속 전용 세션키
static unsigned char aes_key[AES_256_KEY_SIZE];

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

static int send_encrypted_file_data(FILE *fp,
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
        if (!send_all(sock, encrypted, (size_t)out_len)) goto done;
        read_total += (int64_t)n;
        encrypted_total += out_len;
    }

    if (!aes_gcm_encrypt_final(&context, encrypted, &out_len, pv->tag)) {
        goto done;
    }
    pv->has_tag = 1;
    capture_preview(pv->cipher, &pv->cipher_len, encrypted, (size_t)out_len);
    if (!send_all(sock, encrypted, (size_t)out_len)) goto done;
    encrypted_total += out_len;

    ok = encrypted_total == filesize && send_all(sock, pv->tag, AES_GCM_TAG_SIZE);

done:
    aes_gcm_cleanup(&context);
    OPENSSL_cleanse(plain, sizeof(plain));
    return ok;
}

static int recv_encrypted_file_data(FILE *fp,
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
        if (!recv_all(sock, encrypted, n)) goto done;
        capture_preview(pv->cipher, &pv->cipher_len, encrypted, n);
        if (!aes_gcm_decrypt_update(&context, encrypted, (int)n, plain, &out_len) ||
            fwrite(plain, 1, (size_t)out_len, fp) != (size_t)out_len ||
            EVP_DigestUpdate(hash_ctx, plain, (size_t)out_len) <= 0) {
            goto done;
        }
        received += (int64_t)n;
        plain_total += out_len;
    }

    if (!recv_all(sock, pv->tag, AES_GCM_TAG_SIZE)) goto done;
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

    int64_t filesize = 0;
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
    memcpy(fname_buf, filename, strnlen(filename, sizeof(fname_buf) - 1));
    info.filesize = filesize;
    info.sign_len = (int32_t)sign_len;
    memcpy(info.hash, hash, SHA256_DIGEST_LENGTH);
    if (!aes_generate_iv(info.iv)) {
        printf("AES-GCM IV 생성 실패\n");
        free(sign);
        fclose(fp);
        return;
    }

    Aes_Preview pv = {0};
    int ok = send_all(sock, command, sizeof(command)) &&
             send_all(sock, fname_buf, sizeof(fname_buf)) &&
             send_all(sock, &info, sizeof(info)) &&
             send_all(sock, sign, sign_len) &&
             send_encrypted_file_data(fp, filesize, info.iv, &signed_info, &pv);
    fclose(fp);

    // 전송이 끝나면 서버의 검증 결과(OK/FAIL)를 받음
    char ack[ACK_SIZE] = {0};
    int verified = ok && recv_all(sock, ack, sizeof(ack)) && strcmp(ack, "OK") == 0;

    printf("[업로드] %s (%lld byte)\n", filename, (long long)filesize);
    printf("  SHA-256 ");
    print_short_hex(hash, SHA256_DIGEST_LENGTH);
    printf(" / Ed25519 서명 ");
    print_short_hex(sign, sign_len);
    printf(" (%s)\n", CLIENT_PRIVATE_KEY);
    printf("  AES-256-GCM 암호화: ");
    print_aes_preview(info.iv, &pv);
    printf("\n");
    if (!ok) printf("  ==> [업로드 실패] 전송 중 오류\n");
    else if (!verified) printf("  ==> [업로드(검증) 실패] 서버가 검증에 실패해 저장하지 않음\n");
    else printf("  ==> [업로드(검증) 완료]\n");

    free(sign);
}

void do_get(const char *filename) {
    char command[COMMAND_SIZE] = "down";
    char fname_buf[NAME_SIZE] = {0};
    memcpy(fname_buf, filename, strnlen(filename, sizeof(fname_buf) - 1));

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
    char save_path[512], tmp_name[540];
    if (!build_file_path(save_path, sizeof(save_path), save_name)) {
        printf("잘못된 파일명입니다: %s\n", filename);
        return;
    }
    // 같은 폴더에서 클라이언트를 여러 개 실행해도 임시 파일이 겹치지 않도록 PID를 붙임
    snprintf(tmp_name, sizeof(tmp_name), "%s.%d.tmp", save_path, (int)getpid());

    FILE *fp = fopen(tmp_name, "wb");
    if (!fp) {
        perror("파일 저장 실패");
        return;
    }

    Signed_Info signed_info;
    make_signed_info(&signed_info, save_name, info.filesize, info.hash);
    unsigned char recv_hash[SHA256_DIGEST_LENGTH];
    Aes_Preview pv = {0};
    int ok = recv_encrypted_file_data(fp, info.filesize, info.iv, &signed_info, recv_hash, &pv);
    fclose(fp);

    int hash_ok = ok && memcmp(recv_hash, info.hash, SHA256_DIGEST_LENGTH) == 0;
    int sign_ok = hash_ok && eddsa_verify_with_key((unsigned char *)&signed_info, sizeof(signed_info), sign, sizeof(sign), SERVER_PUBLIC_KEY);
    int save_ok = sign_ok && rename(tmp_name, save_path) == 0;

    printf("[다운로드] %s (%lld byte)\n", filename, (long long)info.filesize);
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
    printf(", %s)\n", SERVER_PUBLIC_KEY);

    if (save_ok) {
        printf("  ==> [다운로드(검증) 완료]\n");
    } else {
        remove(tmp_name);
        printf("  ==> [다운로드(검증) 실패] 저장하지 않음\n");
    }
}

// 다운로드 중인 임시 파일(파일명.PID.tmp)은 목록에서 제외
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

// 클라이언트 Files 디렉토리의 일반 파일 목록을 이름순으로 만듦
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
        if (is_transfer_temp_file(ent->d_name) ||
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

// 터미널에 표시되는 폭 (한글 등 3바이트 이상 UTF-8 문자는 2칸, 이어지는 바이트는 0칸)
static int display_width(const char *s) {
    int width = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x80) width += 1;
        else if (*p >= 0xE0) width += 2;
        else if (*p >= 0xC0) width += 1;
    }
    return width;
}

static void print_file_table(const List_Entry *list, int32_t count) {
    const int header_width = display_width("파일명");
    int name_width = header_width;

    if (count == 0) return;
    // 가장 긴 파일명 폭에 맞춰 크기 열을 정렬
    for (int32_t i = 0; i < count; i++) {
        int w = display_width(list[i].filename);
        if (w > name_width) name_width = w;
    }
    printf("  번호  파일명%*s      크기(byte)\n", name_width - header_width, "");
    for (int32_t i = 0; i < count; i++) {
        printf("  %4d  %s%*s  %14lld\n", (int)(i + 1), list[i].filename,
               name_width - display_width(list[i].filename), "", (long long)list[i].filesize);
    }
}

// 클라이언트 Files 목록을 출력하고, 성공 시 목록을 out 으로 넘김 (호출한 쪽에서 free)
static int show_client_list(List_Entry **out, int32_t *count) {
    if (!collect_file_list(out, count)) {
        printf("[내 파일 목록] %s/ 폴더를 읽을 수 없습니다.\n", FILE_DIR);
        return 0;
    }
    if (*count == 0) printf("[내 파일 목록] %s/ - 파일 없음\n", FILE_DIR);
    else printf("[내 파일 목록] %s/ - %d개\n", FILE_DIR, (int)*count);
    print_file_table(*out, *count);
    return 1;
}

// 서버에 list 요청 -> 암호화된 목록 수신/인증 -> 출력. 성공 시 목록을 out 으로 넘김 (호출한 쪽에서 free)
static int fetch_server_list(List_Entry **out, int32_t *count) {
    char command[COMMAND_SIZE] = "list";
    List_Info info;
    List_Entry *list = NULL;
    unsigned char encrypted[sizeof(List_Entry)];
    unsigned char plain[sizeof(List_Entry) + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[AES_GCM_TAG_SIZE];
    int out_len = 0;
    int ok = 0;
    AesGcmContext context = {0};

    *out = NULL;
    *count = 0;
    if (!send_all(sock, command, sizeof(command)) || !recv_all(sock, &info, sizeof(info))) {
        printf("요청 전송 실패\n");
        return 0;
    }
    if (info.count < 0 || info.count > MAX_LIST_ENTRIES) {
        printf("서버 파일 목록 조회 실패\n");
        return 0;
    }
    if (info.count > 0 && !(list = calloc((size_t)info.count, sizeof(*list)))) {
        printf("메모리 할당 실패\n");
        return 0;
    }

    // 인증 태그 검증이 끝나기 전에는 복호화한 목록을 출력하지 않음
    if (!aes_gcm_decrypt_init(&context, aes_key, info.iv, &info, sizeof(info))) goto done;
    for (int32_t i = 0; i < info.count; i++) {
        if (!recv_all(sock, encrypted, sizeof(encrypted))) goto done;
        if (!aes_gcm_decrypt_update(&context, encrypted, (int)sizeof(encrypted), plain, &out_len) ||
            out_len != (int)sizeof(List_Entry)) {
            goto done;
        }
        memcpy(&list[i], plain, sizeof(List_Entry));
        list[i].filename[NAME_SIZE - 1] = '\0';
    }
    if (!recv_all(sock, tag, sizeof(tag))) goto done;
    ok = aes_gcm_decrypt_final(&context, plain, &out_len, tag) && out_len == 0;

done:
    aes_gcm_cleanup(&context);
    if (ok) {
        if (info.count == 0) printf("[서버 파일 목록] 파일 없음 (AES-256-GCM 복호화/인증: 성공)\n");
        else printf("[서버 파일 목록] %d개 (AES-256-GCM 복호화/인증: 성공)\n", (int)info.count);
        print_file_table(list, info.count);
        *out = list;
        *count = info.count;
    } else {
        printf("[서버 파일 목록] AES-256-GCM 복호화/인증: 실패 -> 인증에 실패하여 목록을 표시하지 않습니다\n");
        free(list);
    }
    return ok;
}

// 번호를 입력받아 목록의 항목을 반환. 0 입력(취소)이나 입력 종료 시 NULL
static const List_Entry *select_from_list(const List_Entry *list, int32_t count, const char *action) {
    char input[32];

    if (count == 0) {
        printf("%s할 파일이 없습니다.\n", action);
        return NULL;
    }
    while (1) {
        printf("%s할 파일 번호를 입력하세요 (1~%d, 취소: 0): ", action, (int)count);
        fflush(stdout);
        if (!read_line(input, sizeof(input))) return NULL;

        char *end = NULL;
        long n = strtol(input, &end, 10);
        if (input[0] == '\0' || *end != '\0' || n < 0 || n > count) {
            printf("잘못된 번호입니다. 다시 입력하세요.\n");
            continue;
        }
        if (n == 0) {
            printf("%s를 취소했습니다.\n", action);
            return NULL;
        }
        printf("\n");   // 번호 입력 줄과 전송 결과 사이 한 줄 띄움
        return &list[n - 1];
    }
}

void do_client_list(void) {
    List_Entry *list = NULL;
    int32_t count = 0;
    show_client_list(&list, &count);
    free(list);
}

void do_server_list(void) {
    List_Entry *list = NULL;
    int32_t count = 0;
    fetch_server_list(&list, &count);
    free(list);
}

// 업로드: 내 파일 목록을 보여주고 번호로 선택
void do_put_select(void) {
    List_Entry *list = NULL;
    int32_t count = 0;
    if (show_client_list(&list, &count)) {
        const List_Entry *selected = select_from_list(list, count, "업로드");
        if (selected) do_put(selected->filename);
    }
    free(list);
}

// 다운로드: 서버 파일 목록을 받아 보여주고 번호로 선택
void do_get_select(void) {
    List_Entry *list = NULL;
    int32_t count = 0;
    if (fetch_server_list(&list, &count)) {
        const List_Entry *selected = select_from_list(list, count, "다운로드");
        if (selected) do_get(selected->filename);
    }
    free(list);
}

static void print_menu(void) {
    printf("\n=========== 메뉴 ===========\n");
    printf(" 1. 업로드          (up)\n");
    printf(" 2. 다운로드        (down)\n");
    printf(" 3. 서버 파일 목록  (slist)\n");
    printf(" 4. 내 파일 목록    (clist)\n");
    printf(" 0. 종료            (exit)\n");
    printf("============================\n");
    printf("번호 또는 명령어 입력: ");
}

// 번호(1~4, 0)와 기존 명령어(up, down, exit 등)를 모두 허용
static Command parse_command(const char *input) {
    if (strcmp(input, "1") == 0 || strcmp(input, "up") == 0) return CMD_UP;
    if (strcmp(input, "2") == 0 || strcmp(input, "down") == 0) return CMD_DOWN;
    if (strcmp(input, "3") == 0 || strcmp(input, "slist") == 0) return CMD_SERVER_LIST;
    if (strcmp(input, "4") == 0 || strcmp(input, "clist") == 0) return CMD_CLIENT_LIST;
    if (strcmp(input, "0") == 0 || strcmp(input, "exit") == 0) return CMD_EXIT;
    return CMD_INVALID;
}

/*
 * X25519 키 교환 (Ed25519 서명으로 상호 인증)
 *   C -> S : 클라이언트 임시 공개키
 *   S -> C : 서버 임시 공개키 + 서버 서명(server_private.pem)
 *   C -> S : 클라이언트 서명(client_private.pem)
 *   S -> C : OK / FAIL
 *   양쪽   : X25519 공유값 -> HKDF-SHA256 -> 이번 접속 전용 AES-256 세션키
 */
static int client_handshake(void) {
    unsigned char client_pub[X25519_KEY_SIZE] = {0};
    unsigned char server_pub[X25519_KEY_SIZE] = {0};
    unsigned char server_sign[ED25519_SIG_LEN] = {0};
    unsigned char salt[X25519_KEY_SIZE * 2];
    unsigned char *client_sign = NULL;
    size_t client_sign_len = 0;
    char ack[ACK_SIZE] = {0};
    int server_recv = 0;
    int server_sign_ok = 0;
    int client_auth_ok = 0;
    int ok = 0;
    Handshake_Info hs;
    EVP_PKEY *client_key = x25519_generate_key(client_pub);
    if (!client_key) {
        printf("X25519 키 생성 실패\n");
        return 0;
    }

    if (!send_all(sock, client_pub, sizeof(client_pub)) ||
        !recv_all(sock, server_pub, sizeof(server_pub)) ||
        !recv_all(sock, server_sign, sizeof(server_sign))) {
        goto done;
    }
    server_recv = 1;

    // 서버 공개키가 진짜 서버가 보낸 것인지 확인 (실패 시 중간자 공격 가능성 -> 즉시 중단)
    make_handshake_info(&hs, "X25519-SERVER", client_pub, server_pub);
    server_sign_ok = eddsa_verify_with_key((unsigned char *)&hs, sizeof(hs), server_sign, sizeof(server_sign), SERVER_PUBLIC_KEY);
    if (!server_sign_ok) goto done;

    make_handshake_info(&hs, "X25519-CLIENT", client_pub, server_pub);
    if (!eddsa_sign_with_key((unsigned char *)&hs, sizeof(hs), &client_sign, &client_sign_len, CLIENT_PRIVATE_KEY) ||
        client_sign_len != ED25519_SIG_LEN ||
        !send_all(sock, client_sign, client_sign_len) ||
        !recv_all(sock, ack, sizeof(ack))) {
        goto done;
    }
    client_auth_ok = strcmp(ack, "OK") == 0;
    if (!client_auth_ok) goto done;

    memcpy(salt, client_pub, X25519_KEY_SIZE);
    memcpy(salt + X25519_KEY_SIZE, server_pub, X25519_KEY_SIZE);
    ok = x25519_derive_session_key(client_key, server_pub, salt, sizeof(salt), aes_key);

done:
    // 진행된 단계까지만 한 줄씩 표시 (실패한 단계에서 멈춤)
    printf("[X25519 키 교환] 임시 공개키: 나 ");
    print_short_hex(client_pub, sizeof(client_pub));
    printf(" / 서버 ");
    if (server_recv) print_short_hex(server_pub, sizeof(server_pub));
    else printf("(수신 실패)");
    printf("\n");
    if (server_recv) {
        printf("  서버 서명 검증(Ed25519): %s (%s)\n",
               server_sign_ok ? "성공" : "실패 -> 가짜 서버일 수 있어 중단", SERVER_PUBLIC_KEY);
    }
    if (client_sign) {
        printf("  서버의 클라이언트 인증: %s (내 서명 ", client_auth_ok ? "성공" : "실패");
        print_short_hex(client_sign, client_sign_len);
        printf(", %s)\n", CLIENT_PRIVATE_KEY);
    }
    if (client_auth_ok) {
        printf("  세션키 유도(X25519 + HKDF-SHA256): %s", ok ? "성공" : "실패");
        if (ok) {
            printf(", 세션키 지문(SHA-256): ");
            print_key_fingerprint(aes_key);
        }
        printf("\n");
    }

    free(client_sign);
    EVP_PKEY_free(client_key);
    return ok;
}

int main(void) {
    char server_ip[64], port_text[16], command[64];
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

    if (!client_handshake()) {
        printf("키 교환 실패. 연결 종료\n");
        close(sock);
        return 1;
    }

    while (1) {
        print_menu();
        fflush(stdout);
        if (!read_line(command, sizeof(command))) break;

        Command cmd = parse_command(command);
        if (cmd == CMD_EXIT) {
            char exit_command[COMMAND_SIZE] = "exit";
            send_all(sock, exit_command, sizeof(exit_command));
            break;
        }

        if (cmd == CMD_INVALID) {
            printf("잘못된 명령입니다. 다시 입력하세요.\n");
            continue;
        }
        printf("\n");   // 메뉴 입력 줄과 결과 사이 한 줄 띄움
        if (cmd == CMD_SERVER_LIST) {
            do_server_list();
            continue;
        }
        if (cmd == CMD_CLIENT_LIST) {
            do_client_list();
            continue;
        }

        // 업로드/다운로드: 목록을 먼저 보여주고 번호로 파일 선택
        if (cmd == CMD_UP) do_put_select();
        else do_get_select();
    }

    close(sock);
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    printf("연결 종료\n");
    return 0;
}
