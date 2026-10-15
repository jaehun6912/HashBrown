#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16

typedef struct {
    EVP_CIPHER_CTX *ctx;
} AesGcmContext;

void aes_gcm_cleanup(AesGcmContext *context);

int aes_load_key(const char *key_path, unsigned char key[AES_256_KEY_SIZE]) {
    FILE *fp = fopen(key_path, "rb");
    if (!fp) return 0;

    size_t key_len = fread(key, 1, AES_256_KEY_SIZE, fp);
    int extra = fgetc(fp);
    int ok = key_len == AES_256_KEY_SIZE && extra == EOF && !ferror(fp);
    fclose(fp);

    if (!ok) OPENSSL_cleanse(key, AES_256_KEY_SIZE);
    return ok;
}

int aes_generate_iv(unsigned char iv[AES_GCM_IV_SIZE]) {
    return RAND_bytes(iv, AES_GCM_IV_SIZE) == 1;
}

static int apply_aad(EVP_CIPHER_CTX *ctx, int encrypt, const void *aad, size_t aad_len) {
    int ignored_len = 0;
    if (aad_len == 0) return 1;
    if (!aad || aad_len > INT_MAX) return 0;

    if (encrypt) {
        return EVP_EncryptUpdate(ctx, NULL, &ignored_len,
                                 (const unsigned char *)aad, (int)aad_len) == 1;
    }
    return EVP_DecryptUpdate(ctx, NULL, &ignored_len,
                             (const unsigned char *)aad, (int)aad_len) == 1;
}

int aes_gcm_encrypt_init(AesGcmContext *context,
                         const unsigned char key[AES_256_KEY_SIZE],
                         const unsigned char iv[AES_GCM_IV_SIZE],
                         const void *aad,
                         size_t aad_len) {
    if (!context || !key || !iv) return 0;
    context->ctx = EVP_CIPHER_CTX_new();
    if (!context->ctx) return 0;

    if (EVP_EncryptInit_ex(context->ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context->ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(context->ctx, NULL, NULL, key, iv) != 1 ||
        !apply_aad(context->ctx, 1, aad, aad_len)) {
        aes_gcm_cleanup(context);
        return 0;
    }
    return 1;
}

int aes_gcm_decrypt_init(AesGcmContext *context,
                         const unsigned char key[AES_256_KEY_SIZE],
                         const unsigned char iv[AES_GCM_IV_SIZE],
                         const void *aad,
                         size_t aad_len) {
    if (!context || !key || !iv) return 0;
    context->ctx = EVP_CIPHER_CTX_new();
    if (!context->ctx) return 0;

    if (EVP_DecryptInit_ex(context->ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context->ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(context->ctx, NULL, NULL, key, iv) != 1 ||
        !apply_aad(context->ctx, 0, aad, aad_len)) {
        aes_gcm_cleanup(context);
        return 0;
    }
    return 1;
}

int aes_gcm_encrypt_update(AesGcmContext *context,
                           const unsigned char *input,
                           int input_len,
                           unsigned char *output,
                           int *output_len) {
    return context && context->ctx && input && output && output_len && input_len >= 0 &&
           EVP_EncryptUpdate(context->ctx, output, output_len, input, input_len) == 1;
}

int aes_gcm_decrypt_update(AesGcmContext *context,
                           const unsigned char *input,
                           int input_len,
                           unsigned char *output,
                           int *output_len) {
    return context && context->ctx && input && output && output_len && input_len >= 0 &&
           EVP_DecryptUpdate(context->ctx, output, output_len, input, input_len) == 1;
}

int aes_gcm_encrypt_final(AesGcmContext *context,
                          unsigned char *output,
                          int *output_len,
                          unsigned char tag[AES_GCM_TAG_SIZE]) {
    if (!context || !context->ctx || !output || !output_len || !tag) return 0;
    return EVP_EncryptFinal_ex(context->ctx, output, output_len) == 1 &&
           EVP_CIPHER_CTX_ctrl(context->ctx, EVP_CTRL_GCM_GET_TAG,
                               AES_GCM_TAG_SIZE, tag) == 1;
}

int aes_gcm_decrypt_final(AesGcmContext *context,
                          unsigned char *output,
                          int *output_len,
                          const unsigned char tag[AES_GCM_TAG_SIZE]) {
    if (!context || !context->ctx || !output || !output_len || !tag) return 0;
    if (EVP_CIPHER_CTX_ctrl(context->ctx, EVP_CTRL_GCM_SET_TAG,
                            AES_GCM_TAG_SIZE, (void *)tag) != 1) {
        return 0;
    }
    return EVP_DecryptFinal_ex(context->ctx, output, output_len) == 1;
}

void aes_gcm_cleanup(AesGcmContext *context) {
    if (!context) return;
    EVP_CIPHER_CTX_free(context->ctx);
    context->ctx = NULL;
}
