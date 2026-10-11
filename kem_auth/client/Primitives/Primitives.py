"""
Primitives.py — Primitives cryptographiques du client KEM-MQTT
*
Reproduction et extension de Samandari & Gritti (2023)
Bibliothèques : liboqs-python (Open Quantum Safe), cryptography

Algorithme : ML-KEM-512 — FIPS 203 (NIST, August 2024)
Dérivation : HKDF-SHA256 (RFC 5869)
Intégrité  : HMAC-SHA256
"""

import os
import hashlib
import hmac as hmac_module
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

KEM_ALGORITHM = 'ML-KEM-512'


# Primitives KEM (ML-KEM-512)

def kem_generate_keypair():
    """
    Génère une paire de clés ML-KEM-512.
    Retourne (pk, sk).
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


def kem_encapsulate(public_key):
    """
    ML-KEM.Encaps() — FIPS 203 §7.2
    Retourne (ciphertext, shared_secret).
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def kem_decapsulate(ciphertext, secret_key):
    """
    ML-KEM.Decaps() — FIPS 203 §7.3
    Retourne shared_secret.
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# Dérivation de clé de session (HKDF-SHA256)
# 

def derive_session_key(ss_e, ss_s, r_c, r_b):
    """
    Dérive K_sess à partir des deux secrets KEM et des deux nonces.
        IKM  = ss_e || ss_s
        salt = r_c  || r_b
        info = b'KEM-MQTT-v1'
    Identique à derive_session_key() de primitives.c (broker).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=r_c + r_b,
        info=b'KEM-MQTT-v1',
    )
    return hkdf.derive(ss_e + ss_s)



# Intégrité (HMAC-SHA256)

def compute_hmac(key, *messages):
    """
    HMAC-SHA256 sur la concaténation des messages.
        tau_c = compute_hmac(K_sess, LABEL_CLIENT_FINISHED, *T)
        tau_b = compute_hmac(K_sess, LABEL_BROKER_FINISHED, *T)
    """
    h = hmac_module.new(key, digestmod=hashlib.sha256)
    for msg in messages:
        h.update(msg)
    return h.digest()


def verify_hmac(key, expected_hmac, *messages):
    """Vérifie un HMAC-SHA256 en temps constant. Retourne True/False."""
    computed = compute_hmac(key, *messages)
    return hmac_module.compare_digest(computed, expected_hmac)


def random_nonce(size=32):
    """Nonce aléatoire cryptographiquement sûr."""
    return os.urandom(size)
