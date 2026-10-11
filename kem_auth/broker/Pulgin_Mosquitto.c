/* Pulgin_Mosquitto.c - plugin d'authentification KEM pour Mosquitto (auth_kem.so)
 *
 *   Description
 *   Implémente une authentification post-quantique du broker par KEM pour
 *   MQTT 5.0, fondée sur le schéma proposé par Samandari et Gritti [1]. Elle
 *   s'exécute dans le broker Mosquitto via le mécanisme d'Enhanced
 *   Authentication (paquet AUTH), sans modification du protocole MQTT.
 *   Les deux échanges de clés utilisent ML-KEM-512 ; la dérivation de clé et les vérifications finales utilisent HKDF-SHA256 et HMAC-SHA256 (dans primitives.c).
 *   Méthode d'authentification : "KEM".
 *
 * Les messages :
 *   CONNECT    client -> broker : r_c || pk_e
 *   AUTH 0x18  broker -> client : r_b || ct_e || cert
 *   AUTH 0x18  client -> broker : ct_s || tau_c
 *   CONNACK    broker -> client : tau_b
 *
 * Ce que chacun calcule :
 *   (ct_e, ss_e) = Encaps(pk_e)     côté broker, pk_e vient du client
 *   (ct_s, ss_s) = Encaps(pk_s)     côté client, pk_s vient du certificat
 *   K_sess = HKDF-SHA256(ss_e || ss_s, sel = r_c || r_b, info = "KEM-MQTT-v1")
 *   T      = r_c || pk_e || r_b || ct_e || cert || ct_s
 *   tau_c  = HMAC(K_sess, "KEM-MQTT client finished" || T)
 *   tau_b  = HMAC(K_sess, "KEM-MQTT broker finished" || T)
 *
 * cert est le certificat X.509 (format DER) qui contient pk_s. Il est signé
 * par notre CA en ML-DSA-44.
 *
 * Avant de lancer le broker (une seule fois) :
 *   - generate_broker_keys.py crée la paire statique pk_s / sk_s
 *   - ca/generate_certificate.sh crée le certificat (OpenSSL 3.5)
 * Le broker charge ces fichiers au démarrage. Le client n'a besoin que de
 * ca.crt : il vérifie le certificat, puis récupère pk_s dedans.
 
 * Compilation :
 *   gcc -I<mosquitto>/include -fPIC -shared Pulgin_Mosquitto.c primitives.c \
 *       -o auth_kem.so -loqs -lssl -lcrypto
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

/* Paramètres */
#define AUTH_METHOD        "KEM"
#define DEFAULT_SK_PATH    "/mosquitto/keys/broker_sk_s.bin"
#define DEFAULT_PK_PATH    "/mosquitto/keys/broker_pk_s.bin"
#define DEFAULT_CERT_PATH  "/mosquitto/keys/broker_cert.der"

#define NONCE_LEN   32
#define PK_LEN      OQS_KEM_ml_kem_512_length_public_key     
#define SK_LEN      OQS_KEM_ml_kem_512_length_secret_key     
#define CT_LEN      OQS_KEM_ml_kem_512_length_ciphertext     
#define SS_LEN      OQS_KEM_ml_kem_512_length_shared_secret 
#define HMAC_LEN    32

#define CERT_MAX_LEN        8192                             

#define CLIENT_HELLO_LEN            
/* BROKER_HELLO = r_b || ct_e || cert : taille variable (800 + g_cert_len) */
#define CLIENT_FINISHED_LEN (CT_LEN + HMAC_LEN)           

/* Labels HMAC : identiques au client Python (24 octets, sans '\0') */
#define LABEL_CLIENT_FINISHED "KEM-MQTT client finished"
#define LABEL_BROKER_FINISHED "KEM-MQTT broker finished"
#define LABEL_LEN 24

/* Transcript HMAC = label || r_c || pk_e || r_b || ct_e || cert || ct_s
 * Taille fixe sans cert = 2424 ; buffer dimensionné pour le cert maximal */
#define HMAC_FIXED_LEN (LABEL_LEN + 2 * NONCE_LEN + PK_LEN + 2 * CT_LEN)   
#define HMAC_DATA_MAX  (HMAC_FIXED_LEN + CERT_MAX_LEN)

/* ── État du handshake entre la phase 2 et la phase 4 ─────────
 * Une seule session : un seul client se connecte à la fois. */
typedef struct {
    uint8_t r_c[NONCE_LEN];
    uint8_t pk_e[PK_LEN];
    uint8_t r_b[NONCE_LEN];
    uint8_t ct_e[CT_LEN];
    uint8_t ss_e[SS_LEN];       
} kem_session_t;

static mosquitto_plugin_id_t *mosq_pid = NULL;
static OQS_KEM *g_kem = NULL;
static uint8_t  g_pk_s[PK_LEN];     /* clé publique statique (Phase 0) */
static uint8_t  g_sk_s[SK_LEN];     /* clé secrète statique  (Phase 0) */
static uint8_t  g_cert[CERT_MAX_LEN]; /* certificat X.509 DER de pk_s (Phase 0) */
static size_t   g_cert_len = 0;       /* taille réelle du certificat */
static kem_session_t g_session;


/*  Lecture d'un fichier de clé de taille exacte */
static int load_key_file(const char *path, uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    if(f == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[KEM] Impossible d'ouvrir %s : %s",
                             path, strerror(errno));
        return 0;
    }
    size_t n = fread(buf, 1, len, f);
    int extra = fgetc(f);
    fclose(f);

    if(n != len || extra != EOF){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[KEM] %s : taille incorrecte (attendu %zu octets)",
                             path, len);
        return 0;
    }
    return 1;
}


/* Lecture d'un fichier de taille variable (certificat DER)
 * Lit au plus max_len octets ; la taille lue est écrite dans *out_len*/
static int load_cert_file(const char *path, uint8_t *buf, size_t max_len, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if(f == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[KEM] Impossible d'ouvrir %s : %s",
                             path, strerror(errno));
        return 0;
    }
    size_t n = fread(buf, 1, max_len, f);
    int extra = fgetc(f);
    fclose(f);

    if(n == 0 || extra != EOF){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[KEM] %s : vide ou plus grand que %zu octets",
                             path, max_len);
        return 0;
    }
    *out_len = n;
    return 1;
}


/* PHASE 2 — CONNECT reçu : CLIENT_HELLO → BROKER_HELLO*/
static int kem_auth_start(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_extended_auth *ed = event_data;
    kem_session_t *s = &g_session;
    uint8_t *out = NULL;
    size_t hello_len = NONCE_LEN + CT_LEN + g_cert_len;

    UNUSED(event);
    UNUSED(userdata);

    /* Méthode d'un autre plugin : on laisse la main */
    if(ed->auth_method == NULL || strcmp(ed->auth_method, AUTH_METHOD) != 0){
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    /* Contrôle de longueur avant toute lecture : AuthData = r_c || pk_e */
    if(ed->data_in == NULL || ed->data_in_len != CLIENT_HELLO_LEN){
        mosquitto_log_printf(MOSQ_LOG_WARNING,
                "[KEM] CLIENT_HELLO rejeté : %u octets reçus, %d attendus",
                (unsigned)ed->data_in_len, CLIENT_HELLO_LEN);
        return MOSQ_ERR_AUTH;
    }

    OQS_MEM_cleanse(s, sizeof(*s));
    memcpy(s->r_c,  ed->data_in, NONCE_LEN);
    memcpy(s->pk_e, (const uint8_t *)ed->data_in + NONCE_LEN, PK_LEN);

    /* r_b ← aléatoire ; (ct_e, ss_e) ← ML-KEM.Encaps(pk_e) */
    OQS_randombytes(s->r_b, NONCE_LEN);
    if(OQS_KEM_encaps(g_kem, s->ct_e, s->ss_e, s->pk_e) != OQS_SUCCESS){
        goto fail;
    }

    /* BROKER_HELLO : r_b || ct_e || cert */
    out = malloc(hello_len);
    if(out == NULL){
        goto fail;
    }
    memcpy(out,                      s->r_b,  NONCE_LEN);
    memcpy(out + NONCE_LEN,          s->ct_e, CT_LEN);
    memcpy(out + NONCE_LEN + CT_LEN, g_cert,  g_cert_len);

    ed->data_out     = out;
    ed->data_out_len = hello_len;

    mosquitto_log_printf(MOSQ_LOG_INFO, "[KEM] BROKER_HELLO envoyé à %s (%zu octets)",
            mosquitto_client_id(ed->client), hello_len);
    return MOSQ_ERR_AUTH_CONTINUE;

fail:
    mosquitto_log_printf(MOSQ_LOG_ERR, "[KEM] Erreur interne pendant la phase 2");
    OQS_MEM_cleanse(s, sizeof(*s));
    return MOSQ_ERR_AUTH;
}


/* PHASE 4 — AUTH reçu : CLIENT_FINISHED → CONNACK (tau_b)*/
static int kem_auth_continue(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_extended_auth *ed = event_data;
    kem_session_t *s = &g_session;
    const uint8_t *ct_s = NULL;
    const uint8_t *tau_c = NULL;
    uint8_t ss_s[SS_LEN];
    uint8_t k_sess[32];
    uint8_t hmac_data[HMAC_DATA_MAX];
    size_t hmac_len = HMAC_FIXED_LEN + g_cert_len;
    uint8_t *out = NULL;
    uint8_t *p = NULL;
    int rc = MOSQ_ERR_AUTH;

    UNUSED(event);
    UNUSED(userdata);

    if(ed->auth_method == NULL || strcmp(ed->auth_method, AUTH_METHOD) != 0){
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    /* Contrôle de longueur : AuthData = ct_s || tau_c */
    if(ed->data_in == NULL || ed->data_in_len != CLIENT_FINISHED_LEN){
        mosquitto_log_printf(MOSQ_LOG_WARNING,
                "[KEM] CLIENT_FINISHED rejeté : %u octets reçus, %d attendus",
                (unsigned)ed->data_in_len, CLIENT_FINISHED_LEN);
        goto done;
    }
    ct_s  = ed->data_in;
    tau_c = (const uint8_t *)ed->data_in + CT_LEN;

    /* ss_s ← ML-KEM.Decaps(ct_s, sk_s) */
    if(OQS_KEM_decaps(g_kem, ss_s, ct_s, g_sk_s) != OQS_SUCCESS){
        goto done;
    }

    /* K_sess ← HKDF-SHA256(ss_e || ss_s, salt = r_c || r_b) */
    if(!derive_session_key(s->ss_e, ss_s, s->r_c, s->r_b, k_sess)){
        goto done;
    }

    /* Transcript : label || r_c || pk_e || r_b || ct_e || cert || ct_s */
    p = hmac_data + LABEL_LEN;
    memcpy(p, s->r_c,  NONCE_LEN); p += NONCE_LEN;
    memcpy(p, s->pk_e, PK_LEN);    p += PK_LEN;
    memcpy(p, s->r_b,  NONCE_LEN); p += NONCE_LEN;
    memcpy(p, s->ct_e, CT_LEN);    p += CT_LEN;
    memcpy(p, g_cert,  g_cert_len); p += g_cert_len;
    memcpy(p, ct_s,    CT_LEN);

    /* Vérification de tau_c (temps constant) */
    memcpy(hmac_data, LABEL_CLIENT_FINISHED, LABEL_LEN);
    if(!verify_hmac(k_sess, tau_c, hmac_data, hmac_len)){
        mosquitto_log_printf(MOSQ_LOG_WARNING, "[KEM] tau_c invalide pour %s",
                mosquitto_client_id(ed->client));
        goto done;
    }

    /* tau_b, envoyé dans l'AuthenticationData du CONNACK */
    out = malloc(HMAC_LEN);
    if(out == NULL){
        goto done;
    }
    memcpy(hmac_data, LABEL_BROKER_FINISHED, LABEL_LEN);
    if(!compute_hmac(k_sess, hmac_data, hmac_len, out)){
        free(out);
        goto done;
    }

    ed->data_out     = out;
    ed->data_out_len = HMAC_LEN;
    rc = MOSQ_ERR_SUCCESS;

    mosquitto_log_printf(MOSQ_LOG_INFO, "[KEM] Client %s : tau_c valide, tau_b envoyé",
            mosquitto_client_id(ed->client));

done:
    OQS_MEM_cleanse(ss_s, sizeof(ss_s));
    OQS_MEM_cleanse(k_sess, sizeof(k_sess));
    OQS_MEM_cleanse(s, sizeof(*s));
    return rc;
}


/* Initialisation : chargement de (pk_s, sk_s) et du certificat (Phase 0) */
int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data,
                          struct mosquitto_opt *opts, int opt_count)
{
    const char *sk_path = DEFAULT_SK_PATH;
    const char *pk_path = DEFAULT_PK_PATH;
    const char *cert_path = DEFAULT_CERT_PATH;
    uint8_t test_ct[CT_LEN];
    uint8_t test_ss1[SS_LEN];
    uint8_t test_ss2[SS_LEN];
    int pair_ok;
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

    g_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if(g_kem == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[KEM] ML-KEM-512 absent de liboqs");
        return MOSQ_ERR_UNKNOWN;
    }

    if(!load_key_file(sk_path, g_sk_s, SK_LEN) || !load_key_file(pk_path, g_pk_s, PK_LEN)){
        return MOSQ_ERR_UNKNOWN;
    }
    if(!load_cert_file(cert_path, g_cert, CERT_MAX_LEN, &g_cert_len)){
        return MOSQ_ERR_UNKNOWN;
    }

    /* Vérifie que le certificat contient bien pk_s : évite d'envoyer un
     * certificat périmé si les clés ont été régénérées sans lui */
    if(memmem(g_cert, g_cert_len, g_pk_s, PK_LEN) == NULL){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[KEM] %s ne contient pas pk_s : relance generate_certificate.sh",
                cert_path);
        return MOSQ_ERR_UNKNOWN;
    }

    /* Vérifie que pk_s et sk_s forment bien une paire :
     * Encaps(pk_s) puis Decaps(sk_s) doivent donner le même secret */
    pair_ok = OQS_KEM_encaps(g_kem, test_ct, test_ss1, g_pk_s) == OQS_SUCCESS
           && OQS_KEM_decaps(g_kem, test_ss2, test_ct, g_sk_s) == OQS_SUCCESS
           && memcmp(test_ss1, test_ss2, SS_LEN) == 0;
    OQS_MEM_cleanse(test_ss1, sizeof(test_ss1));
    OQS_MEM_cleanse(test_ss2, sizeof(test_ss2));
    if(!pair_ok){
        mosquitto_log_printf(MOSQ_LOG_ERR, "[KEM] pk_s et sk_s ne correspondent pas");
        return MOSQ_ERR_UNKNOWN;
    }

    rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_EXT_AUTH_START, kem_auth_start, NULL, NULL);
    if(rc != MOSQ_ERR_SUCCESS){
        return rc;
    }
    rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_EXT_AUTH_CONTINUE, kem_auth_continue, NULL, NULL);
    if(rc != MOSQ_ERR_SUCCESS){
        return rc;
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "[KEM] Plugin prêt : ML-KEM-512, certificat %s (%zu octets)",
            cert_path, g_cert_len);
    return MOSQ_ERR_SUCCESS;
}


int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
    UNUSED(user_data);
    UNUSED(opts);
    UNUSED(opt_count);

    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_EXT_AUTH_START, kem_auth_start, NULL);
    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_EXT_AUTH_CONTINUE, kem_auth_continue, NULL);

    OQS_MEM_cleanse(&g_session, sizeof(g_session));
    OQS_MEM_cleanse(g_sk_s, sizeof(g_sk_s));
    OQS_KEM_free(g_kem);
    g_kem = NULL;

    return MOSQ_ERR_SUCCESS;
}
