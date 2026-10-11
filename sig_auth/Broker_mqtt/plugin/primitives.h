/* primitives.h
 * Fonctions cryptographiques pour le plugin SIG-MQTT
 * (HKDF-SHA256 et HMAC-SHA256 via OpenSSL 3.x)
 */

#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#include <stdint.h>
#include <stddef.h>

/* HKDF-SHA256 — clé de session du schéma SIG
 * IKM  = pms            
 * salt = r_c || r_b     
 * info = "SIG-MQTT-v1"
 * Sortie : session_key
 * Retourne 1 si succès, 0 sinon
 */
int derive_session_key_sig(
    const uint8_t *pms,
    const uint8_t *r_c,
    const uint8_t *r_b,
    uint8_t *session_key
);

/* HMAC-SHA256 — calcul d'intégrité
 * Entrées : key (32 bytes), data, data_len
 * Sortie  : hmac_out (32 bytes)
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
