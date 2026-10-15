#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int eddsa_sign_with_key(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len, const char *key_path) {
    FILE *fp = fopen(key_path, "r");
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;

    *sig = NULL;
    *sig_len = 0;
    if (!fp) {
        perror("개인키 열기 실패");
        return 0;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) goto done;

    ctx = EVP_MD_CTX_new();
    if (!ctx) goto done;

    // EdDSA는 해시 알고리즘을 NULL로 전달함.
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) <= 0) goto done;
    if (EVP_DigestSign(ctx, NULL, sig_len, msg, msg_len) <= 0) goto done;

    *sig = (unsigned char *)malloc(*sig_len);
    if (!*sig) goto done;
    if (EVP_DigestSign(ctx, *sig, sig_len, msg, msg_len) <= 0) {
        free(*sig);
        *sig = NULL;
        goto done;
    }

    ok = 1;

done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

int eddsa_verify_with_key(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len, const char *key_path) {
    FILE *fp = fopen(key_path, "r");
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if (!fp) {
        perror("공개키 열기 실패");
        return 0;
    }

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) goto done;

    ctx = EVP_MD_CTX_new();
    if (!ctx) goto done;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) <= 0) goto done;

    ret = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1;

done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}
