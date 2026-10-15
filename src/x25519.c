#include <stddef.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define X25519_KEY_SIZE 32
#define AES_256_KEY_SIZE 32
#define HKDF_INFO "X25519-HKDF-SHA256 AES-256-GCM session key"

// 접속마다 새로 만드는 임시(ephemeral) X25519 키쌍. 공개키는 pub 에 32바이트로 저장
EVP_PKEY *x25519_generate_key(unsigned char pub[X25519_KEY_SIZE]) {
    EVP_PKEY *key = NULL;
    size_t pub_len = X25519_KEY_SIZE;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &key) <= 0) key = NULL;
    EVP_PKEY_CTX_free(ctx);

    if (key && (EVP_PKEY_get_raw_public_key(key, pub, &pub_len) <= 0 || pub_len != X25519_KEY_SIZE)) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    return key;
}

// 내 개인키 + 상대 공개키 -> X25519 공유 비밀값 -> HKDF-SHA256 -> AES-256 세션키
int x25519_derive_session_key(EVP_PKEY *own_key,
                              const unsigned char peer_pub[X25519_KEY_SIZE],
                              const unsigned char *salt,
                              size_t salt_len,
                              unsigned char session_key[AES_256_KEY_SIZE]) {
    unsigned char shared[X25519_KEY_SIZE];
    size_t shared_len = sizeof(shared);
    size_t key_len = AES_256_KEY_SIZE;
    int ok = 0;
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, X25519_KEY_SIZE);
    EVP_PKEY_CTX *dh_ctx = EVP_PKEY_CTX_new(own_key, NULL);
    EVP_PKEY_CTX *kdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!peer || !dh_ctx || !kdf_ctx) goto done;

    if (EVP_PKEY_derive_init(dh_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dh_ctx, peer) <= 0 ||
        EVP_PKEY_derive(dh_ctx, shared, &shared_len) <= 0 ||
        shared_len != sizeof(shared)) {
        goto done;
    }

    // 공유 비밀값을 그대로 쓰지 않고 HKDF로 AES 키를 유도함 (salt = 양쪽 임시 공개키)
    if (EVP_PKEY_derive_init(kdf_ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(kdf_ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(kdf_ctx, salt, (int)salt_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(kdf_ctx, shared, (int)shared_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(kdf_ctx, (const unsigned char *)HKDF_INFO, (int)strlen(HKDF_INFO)) <= 0 ||
        EVP_PKEY_derive(kdf_ctx, session_key, &key_len) <= 0 ||
        key_len != AES_256_KEY_SIZE) {
        goto done;
    }
    ok = 1;

done:
    if (!ok) OPENSSL_cleanse(session_key, AES_256_KEY_SIZE);
    OPENSSL_cleanse(shared, sizeof(shared));
    EVP_PKEY_CTX_free(kdf_ctx);
    EVP_PKEY_CTX_free(dh_ctx);
    EVP_PKEY_free(peer);
    return ok;
}
