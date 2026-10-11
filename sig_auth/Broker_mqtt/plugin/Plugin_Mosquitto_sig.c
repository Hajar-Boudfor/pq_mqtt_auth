/* Plugin_Mosquitto_sig.c
 *
 * Plugin Mosquitto pour l'authentification post-quantique par signature
 * (schéma SIG, Figure 11 du rapport).
 *   ML-DSA-44  (FIPS 204) : identité statique du broker, signature sigma_s
 *   ML-KEM-512 (FIPS 203) : échange de clé éphémère (PFS)
 *   HKDF-SHA256, HMAC-SHA256 : primitives.c
 *
 * Handshake MQTT5 Enhanced Authentication (AuthenticationMethod = "SIG") :
 *   CONNECT   client → broker : r_c                                (32 B)
 *   AUTH 0x18 broker → client : r_b || sigma_s || cert || pk_kem   (~7257 B)
 *   AUTH 0x18 client → broker : ct || tau_c                        (800 B)
 *   CONNACK   broker → client : tau_b                              (32 B)
 *
 *   sigma_s = ML-DSA-44.Sign(sk_s, r_c || r_b || pk_kem)
 *   K_sess  = HKDF-SHA256(IKM = pms, salt = r_c || r_b, info = "SIG-MQTT-v1")
 *   tau_c   = HMAC(K_sess, "SIG-MQTT client finished" || r_c || r_b || pk_kem || sigma_s || ct)
 *   tau_b   = HMAC(K_sess, "SIG-MQTT broker finished" || r_c || r_b || pk_kem || sigma_s || ct)
 *
 *   cert    = certificat X.509 de pk_s, signé par la CA (ML-DSA-44), format DER
 *
 * Phase 0 (hors ligne) : la paire (pk_s, sk_s) est générée une seule fois par
 * generate_broker_keys.py, et cert par generate_certificate.sh (OpenSSL 3.5).
 * Le plugin les charge au démarrage, il ne les régénère jamais.
 *
 * Options mosquitto.conf :
 *   plugin_opt_sk_path  chemin de broker_sk_s.bin  
 *   plugin_opt_pk_path  chemin de broker_pk_s.bin  
 *   plugin_opt_cert_path chemin de broker_cert.der  
 *
 * Compile avec :
 *   gcc -I<mosquitto>/include -fPIC -shared Plugin_Mosquitto_sig.c primitives.c \
 *       -o auth_sig.so -loqs -lssl -lcrypto
 */

#define _GNU_SOURCE          
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mosquitto.h>
#include <oqs/oqs.h>

#include "primitives.h"

#ifndef UNUSED
#  define UNUSED(A) (void)(A)
#endif

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

/* Paramètre*/
#define AUTH_METHOD        "SIG"
#define DEFAULT_SK_PATH    "/mosquitto/keys/broker_sk_s.bin"
#define DEFAULT_PK_PATH    "/mosquitto/keys/broker_pk_s.bin"
#define DEFAULT_CERT_PATH  "/mosquitto/keys/broker_cert.der"

#define NONCE_LEN   32
#define PK_S_LEN    OQS_SIG_ml_dsa_44_length_public_key       
#define SK_S_LEN    OQS_SIG_ml_dsa_44_length_secret_key     
#define SIG_LEN     OQS_SIG_ml_dsa_44_length_signature       
#define PK_KEM_LEN  OQS_KEM_ml_kem_512_length_public_key     
#define SK_KEM_LEN  OQS_KEM_ml_kem_512_length_secret_key  
#define CT_LEN      OQS_KEM_ml_kem_512_length_ciphertext     
#define SS_LEN      OQS_KEM_ml_kem_512_length_shared_secret
#define HMAC_LEN    32

#define CERT_MAX_LEN        8192                                           
#define CLIENT_FINISHED_LEN (CT_LEN + HMAC_LEN)                             
/* Labels HMAC : identiques à Primitives.py (24 octets, sans '\0') */
#define LABEL_CLIENT_FINISHED "SIG-MQTT client finished"
#define LABEL_BROKER_FINISHED "SIG-MQTT broker finished"
#define LABEL_LEN 24

/* Transcript HMAC = label || r_c || r_b || pk_kem || sigma_s || ct */
#define HMAC_DATA_LEN (LABEL_LEN + 2 * NONCE_LEN + PK_KEM_LEN + SIG_LEN + CT_LEN)  /* 4076 */

/* État du handshake entre la phase 2 et la phase 4 */
typedef struct {
    uint8_t r_c[NONCE_LEN];
    uint8_t r_b[NONCE_LEN];
    uint8_t pk_kem[PK_KEM_LEN];
    uint8_t sk_kem[SK_KEM_LEN];       
    uint8_t sigma_s[SIG_LEN];
} sig_session_t;

static mosquitto_plugin_id_t *mosq_pid = NULL;
static OQS_SIG *g_sig = NULL;
static OQS_KEM *g_kem = NULL;
static uint8_t  g_pk_s[PK_S_LEN];     /* clé publique statique (Phase 0) */
static uint8_t  g_sk_s[SK_S_LEN];     /* clé secrète statique  (Phase 0) */
static uint8_t  g_cert[CERT_MAX_LEN]; /* certificat X.509 DER de pk_s (Phase 0) */
static size_t   g_cert_len = 0;        /* taille réelle du certificat */
static sig_session_t g_session;


/* Lecture d'un fichier de clé de taille exact */
static int load_key_file(const char *path, uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    if(f == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[SIG] Impossible d'ouvrir %s : %s",
                             path, strerror(errno));
        return 0;
    }
    size_t n = fread(buf, 1, len, f);
    int extra = fgetc(f);
    fclose(f);

    if(n != len || extra != EOF){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[SIG] %s : taille incorrecte (attendu %zu octets)",
                             path, len);
        return 0;
    }
    return 1;
}



static int load_cert_file(const char *path, uint8_t *buf, size_t max_len, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if(f == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[SIG] Impossible d'ouvrir %s : %s",
                             path, strerror(errno));
        return 0;
    }
    size_t n = fread(buf, 1, max_len, f);
    int extra = fgetc(f);
    fclose(f);

    if(n == 0 || extra != EOF){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[SIG] %s : vide ou plus grand que %zu octets",
                             path, max_len);
        return 0;
    }
    *out_len = n;
    return 1;
}


/*  PHASE 2 — CONNECT reçu : CLIENT_HELLO → BROKER_HELLO*/
static int sig_auth_start(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_extended_auth *ed = event_data;
    sig_session_t *s = &g_session;
    uint8_t transcript[2 * NONCE_LEN + PK_KEM_LEN];
    uint8_t *out = NULL;
    size_t sig_len = 0;
    size_t hello_len = NONCE_LEN + SIG_LEN + g_cert_len + PK_KEM_LEN;

    UNUSED(event);
    UNUSED(userdata);

    /* Méthode d'un autre plugin : on laisse la main */
    if(ed->auth_method == NULL || strcmp(ed->auth_method, AUTH_METHOD) != 0){
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    /* Contrôle de longueur avant toute lecture : AuthData = r_c */
    if(ed->data_in == NULL || ed->data_in_len != NONCE_LEN){
        mosquitto_log_printf(MOSQ_LOG_WARNING,
                "[SIG] CLIENT_HELLO rejeté : %u octets reçus, %d attendus",
                (unsigned)ed->data_in_len, NONCE_LEN);
        return MOSQ_ERR_AUTH;
    }

    OQS_MEM_cleanse(s, sizeof(*s));
    memcpy(s->r_c, ed->data_in, NONCE_LEN);

    /* r_b ← aléatoire ; (pk_kem, sk_kem) ← ML-KEM.KeyGen() éphémère */
    OQS_randombytes(s->r_b, NONCE_LEN);
    if(OQS_KEM_keypair(g_kem, s->pk_kem, s->sk_kem) != OQS_SUCCESS){
        goto fail;
    }

    /* sigma_s ← ML-DSA.Sign(sk_s, r_c || r_b || pk_kem) */
    memcpy(transcript,                 s->r_c,    NONCE_LEN);
    memcpy(transcript + NONCE_LEN,     s->r_b,    NONCE_LEN);
    memcpy(transcript + 2 * NONCE_LEN, s->pk_kem, PK_KEM_LEN);

    if(OQS_SIG_sign(g_sig, s->sigma_s, &sig_len,
                    transcript, sizeof(transcript), g_sk_s) != OQS_SUCCESS
            || sig_len != SIG_LEN){
        goto fail;
    }

    /* BROKER_HELLO : r_b || sigma_s || cert || pk_kem */
    out = malloc(hello_len);
    if(out == NULL){
        goto fail;
    }
    memcpy(out,                                    s->r_b,     NONCE_LEN);
    memcpy(out + NONCE_LEN,                        s->sigma_s, SIG_LEN);
    memcpy(out + NONCE_LEN + SIG_LEN,              g_cert,     g_cert_len);
    memcpy(out + NONCE_LEN + SIG_LEN + g_cert_len, s->pk_kem,  PK_KEM_LEN);

    ed->data_out     = out;
    ed->data_out_len = hello_len;

    mosquitto_log_printf(MOSQ_LOG_INFO, "[SIG] BROKER_HELLO envoyé à %s (%zu octets)",
            mosquitto_client_id(ed->client), hello_len);
    return MOSQ_ERR_AUTH_CONTINUE;

fail:
    mosquitto_log_printf(MOSQ_LOG_ERR, "[SIG] Erreur interne pendant la phase 2");
    OQS_MEM_cleanse(s, sizeof(*s));
    return MOSQ_ERR_AUTH;
}


/* PHASE 4 — AUTH reçu : CLIENT_FINISHED → CONNACK (tau_b) */
static int sig_auth_continue(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_extended_auth *ed = event_data;
    sig_session_t *s = &g_session;
    const uint8_t *ct = NULL;
    const uint8_t *tau_c = NULL;
    uint8_t pms[SS_LEN];
    uint8_t k_sess[32];
    uint8_t hmac_data[HMAC_DATA_LEN];
    uint8_t *out = NULL;
    uint8_t *p = NULL;
    int rc = MOSQ_ERR_AUTH;

    UNUSED(event);
    UNUSED(userdata);

    if(ed->auth_method == NULL || strcmp(ed->auth_method, AUTH_METHOD) != 0){
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    /* Contrôle de longueur : AuthData = ct || tau_c */
    if(ed->data_in == NULL || ed->data_in_len != CLIENT_FINISHED_LEN){
        mosquitto_log_printf(MOSQ_LOG_WARNING,
                "[SIG] CLIENT_FINISHED rejeté : %u octets reçus, %d attendus",
                (unsigned)ed->data_in_len, CLIENT_FINISHED_LEN);
        goto done;
    }
    ct    = ed->data_in;
    tau_c = (const uint8_t *)ed->data_in + CT_LEN;

    /* pms ← ML-KEM.Decaps(sk_kem, ct), puis effacement de sk_kem (PFS) */
    if(OQS_KEM_decaps(g_kem, pms, ct, s->sk_kem) != OQS_SUCCESS){
        goto done;
    }
    OQS_MEM_cleanse(s->sk_kem, SK_KEM_LEN);

    /* K_sess ← HKDF-SHA256(pms, salt = r_c || r_b) */
    if(!derive_session_key_sig(pms, s->r_c, s->r_b, k_sess)){
        goto done;
    }

    /* Transcript : label || r_c || r_b || pk_kem || sigma_s || ct */
    p = hmac_data + LABEL_LEN;
    memcpy(p, s->r_c,     NONCE_LEN);  p += NONCE_LEN;
    memcpy(p, s->r_b,     NONCE_LEN);  p += NONCE_LEN;
    memcpy(p, s->pk_kem,  PK_KEM_LEN); p += PK_KEM_LEN;
    memcpy(p, s->sigma_s, SIG_LEN);    p += SIG_LEN;
    memcpy(p, ct,         CT_LEN);

    /* Vérification de tau_c (temps constant) */
    memcpy(hmac_data, LABEL_CLIENT_FINISHED, LABEL_LEN);
    if(!verify_hmac(k_sess, tau_c, hmac_data, sizeof(hmac_data))){
        mosquitto_log_printf(MOSQ_LOG_WARNING, "[SIG] tau_c invalide pour %s",
                mosquitto_client_id(ed->client));
        goto done;
    }

    /* tau_b, envoyé dans l'AuthenticationData du CONNACK */
    out = malloc(HMAC_LEN);
    if(out == NULL){
        goto done;
    }
    memcpy(hmac_data, LABEL_BROKER_FINISHED, LABEL_LEN);
    if(!compute_hmac(k_sess, hmac_data, sizeof(hmac_data), out)){
        free(out);
        goto done;
    }

    ed->data_out     = out;
    ed->data_out_len = HMAC_LEN;
    rc = MOSQ_ERR_SUCCESS;

    mosquitto_log_printf(MOSQ_LOG_INFO, "[SIG] Client %s authentifié, tau_b envoyé",
            mosquitto_client_id(ed->client));

done:
    OQS_MEM_cleanse(pms, sizeof(pms));
    OQS_MEM_cleanse(k_sess, sizeof(k_sess));
    OQS_MEM_cleanse(s, sizeof(*s));
    return rc;
}


/*  Initialisation : chargement de (pk_s, sk_s) et du certificat (Phase 0) */
int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data,
                          struct mosquitto_opt *opts, int opt_count)
{
    const char *sk_path = DEFAULT_SK_PATH;
    const char *pk_path = DEFAULT_PK_PATH;
    const char *cert_path = DEFAULT_CERT_PATH;
    uint8_t test_sig[SIG_LEN];
    size_t test_sig_len = 0;
    static const uint8_t test_msg[] = "SIG-MQTT key pair check";
    int rc;

    UNUSED(user_data);
    mosq_pid = identifier;

    for(int i = 0; i < opt_count; i++){
        if(strcmp(opts[i].key, "sk_path") == 0){
            sk_path = opts[i].value;
        }else if(strcmp(opts[i].key, "pk_path") == 0){
            pk_path = opts[i].value;
        }else if(strcmp(opts[i].key, "cert_path") == 0){
            cert_path = opts[i].value;
        }
    }

    g_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    g_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if(g_sig == NULL || g_kem == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[SIG] ML-DSA-44 ou ML-KEM-512 absent de liboqs");
        return MOSQ_ERR_UNKNOWN;
    }

    if(!load_key_file(sk_path, g_sk_s, SK_S_LEN) || !load_key_file(pk_path, g_pk_s, PK_S_LEN)){
        return MOSQ_ERR_UNKNOWN;
    }

    if(!load_cert_file(cert_path, g_cert, CERT_MAX_LEN, &g_cert_len)){
        return MOSQ_ERR_UNKNOWN;
    }

    /* Vérifie que le certificat contient bien pk_s : évite d'envoyer un
     * certificat périmé si les clés ont été régénérées sans lui */
    if(memmem(g_cert, g_cert_len, g_pk_s, PK_S_LEN) == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[SIG] %s ne contient pas pk_s : relance generate_certificate.sh",
                cert_path);
        return MOSQ_ERR_UNKNOWN;
    }

    /* Vérifie que pk_s et sk_s forment bien une paire */
    if(OQS_SIG_sign(g_sig, test_sig, &test_sig_len, test_msg, sizeof(test_msg), g_sk_s) != OQS_SUCCESS
            || OQS_SIG_verify(g_sig, test_msg, sizeof(test_msg), test_sig, test_sig_len, g_pk_s) != OQS_SUCCESS){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[SIG] pk_s et sk_s ne correspondent pas");
        return MOSQ_ERR_UNKNOWN;
    }

    rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_EXT_AUTH_START, sig_auth_start, NULL, NULL);
    if(rc != MOSQ_ERR_SUCCESS){
        return rc;
    }
    rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_EXT_AUTH_CONTINUE, sig_auth_continue, NULL, NULL);
    if(rc != MOSQ_ERR_SUCCESS){
        return rc;
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "[SIG] Plugin prêt : ML-DSA-44 + ML-KEM-512, certificat %s (%zu octets)",
            cert_path, g_cert_len);
    return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
    UNUSED(user_data);
    UNUSED(opts);
    UNUSED(opt_count);

    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_EXT_AUTH_START, sig_auth_start, NULL);
    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_EXT_AUTH_CONTINUE, sig_auth_continue, NULL);

    OQS_MEM_cleanse(&g_session, sizeof(g_session));
    OQS_MEM_cleanse(g_sk_s, sizeof(g_sk_s));
    OQS_SIG_free(g_sig);
    OQS_KEM_free(g_kem);
    g_sig = NULL;
    g_kem = NULL;

    return MOSQ_ERR_SUCCESS;
}


