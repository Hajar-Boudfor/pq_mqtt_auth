/* primitives.h
 * Fonctions cryptographiques pour le plugin KEM-MQTT
 */

#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#include <stdint.h>
#include <stddef.h>

/* HKDF-SHA256 — dérivation de la clé de session
 * Entrées : ss_e, ss_s, r_c, r_b 
 * IKM = ss_e || ss_s, salt = r_c || r_b, info = "KEM-MQTT-v1"
 * Sortie  : session_key 
 * Retourne 1 si succès, 0 sinon
 */
int derive_session_key(
    const uint8_t *ss_e,
    const uint8_t *ss_s,
    const uint8_t *r_c,
    const uint8_t *r_b,
    uint8_t *session_key
);

/* HMAC-SHA256 — calcul d'intégrité
 * Entrées : key , data, data_len
 * Sortie  : hmac_out
 * Retourne 1 si succès, 0 sinon
 */
int compute_hmac(
    const uint8_t *key,
    const uint8_t *data, size_t data_len,
    uint8_t *hmac_out
);

/* Vérification HMAC en temps constant
 * Retourne 1 si valide, 0 sinon
 */
int verify_hmac(
    const uint8_t *key,
    const uint8_t *expected,
    const uint8_t *data, size_t data_len
);

#endif
