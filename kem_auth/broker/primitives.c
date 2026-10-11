/* primitives.c
 * Fonctions cryptographiques pour le plugin KEM-MQTT
 * Compile avec : -lssl -lcrypto
 */

#include "primitives.h"

#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/crypto.h>


int derive_session_key(
    const uint8_t *ss_e,
    const uint8_t *ss_s,
    const uint8_t *r_c,
    const uint8_t *r_b,
    uint8_t *session_key)
{
    /* Construire IKM = ss_e || ss_s */
    uint8_t ikm[64];
    memcpy(ikm,      ss_e, 32);
    memcpy(ikm + 32, ss_s, 32);

    /* Construire salt = r_c || r_b */
    uint8_t salt[64];
    memcpy(salt,      r_c, 32);
    memcpy(salt + 32, r_b, 32);

    const char *info = "KEM-MQTT-v1";

    int ok = 0;

    /* HKDF via OpenSSL 3.x EVP_KDF */
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if(kdf == NULL){
        OPENSSL_cleanse(ikm, sizeof(ikm));
        return 0;
    }
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if(ctx == NULL){
        OPENSSL_cleanse(ikm, sizeof(ikm));
        return 0;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_octet_string("key",   ikm,  64),
        OSSL_PARAM_octet_string("salt",  salt, 64),
        OSSL_PARAM_octet_string("info",  (void *)info, strlen(info)),
        OSSL_PARAM_END
    };

    ok = (EVP_KDF_derive(ctx, session_key, 32, params) == 1);
    EVP_KDF_CTX_free(ctx);
    OPENSSL_cleanse(ikm, sizeof(ikm)); 
    return ok;
}


int compute_hmac(
    const uint8_t *key,
    const uint8_t *data, size_t data_len,
    uint8_t *hmac_out)
{
    unsigned int out_len = 0;
    if(HMAC(EVP_sha256(), key, 32, data, data_len, hmac_out, &out_len) == NULL
            || out_len != 32){
        return 0;
    }
    return 1;
}


int verify_hmac(
    const uint8_t *key,
    const uint8_t *expected,
    const uint8_t *data, size_t data_len)
{
    uint8_t computed[32];
    int ok;
    if(!compute_hmac(key, data, data_len, computed)){
        return 0;
    }
    ok = (CRYPTO_memcmp(computed, expected, 32) == 0);
    OPENSSL_cleanse(computed, sizeof(computed));
    return ok;
}
