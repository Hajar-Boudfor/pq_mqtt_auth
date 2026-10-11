"""
Primitives cryptographiques pour KEM-MQTT et SIG-MQTT
Reproduction de Gritti & Samandari (2023)
Bibliothèque : liboqs-python (Open Quantum Safe Project)

Algorithmes :
  - ML-KEM-512 — FIPS 203 (NIST, August 2024)
  - ML-DSA-44  — FIPS 204 (NIST, August 2024)
"""

import os
import hashlib
import hmac as hmac_module
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

KEM_ALGORITHM = 'ML-KEM-512'
SIG_ALGORITHM = 'ML-DSA-44'

ML_DSA_44_PK_BYTES  = 1312
ML_DSA_44_SIG_BYTES = 2420


# Primitives KEM

def kem_generate_keypair():
    """
    Génère une paire de clés KEM.

    Retourne
    --------
    pk : clé publique d'encapsulation
    sk : clé secrète de décapsulation
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


def kem_encapsulate(public_key):
    """
    Encapsule un secret partagé avec la clé publique.
    Correspond à ML-KEM.Encaps() — FIPS 203 §7.2
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def kem_decapsulate(ciphertext, secret_key):
    """
    Décapsule pour récupérer le secret partagé.
    Correspond à ML-KEM.Decaps() — FIPS 203 §7.3
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# Primitives Signature (ML-DSA-44)

def sig_generate_keypair():
    """
    Génère une paire de clés ML-DSA-44.
    Correspond à ML-DSA.KeyGen() — FIPS 204 §5.1
    Utilisée une seule fois, hors ligne (Phase 0), pour l'identité
    statique du broker.

    Retourne
    --------
    pk : clé publique de vérification (1312 bytes)
    sk : clé secrète de signature     (2560 bytes)
    """
    with oqs.Signature(SIG_ALGORITHM) as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
    return pk, sk


def sig_sign(message, secret_key):
    """
    Signe un message avec ML-DSA-44.
    Correspond à ML-DSA.Sign() — FIPS 204 §5.2
    Dans le protocole, c'est le broker (en C) qui signe ; cette
    fonction sert aux tests en Python.
    """
    with oqs.Signature(SIG_ALGORITHM, secret_key) as sig:
        signature = sig.sign(message)
    return signature


def sig_verify(message, signature, public_key):
    """
    Vérifie une signature ML-DSA-44.
    Correspond à ML-DSA.Verify() — FIPS 204 §5.3
    Retourne True si valide, False sinon.
    """
    if len(public_key) != ML_DSA_44_PK_BYTES:
        return False
    if len(signature) != ML_DSA_44_SIG_BYTES:
        return False
    with oqs.Signature(SIG_ALGORITHM) as sig:
        return sig.verify(message, signature, public_key)


def sig_transcript(r_c, r_b, pk_kem):
    """
    Construit le transcript signé par le broker : r_c || r_b || pk_kem.
    Le broker (C) doit concaténer exactement dans le même ordre.
    """
    return r_c + r_b + pk_kem


# Dérivation de clé de session

def derive_session_key(ss_e, ss_s, r_c, r_b):
    """
    Dérive la clé de session à partir de deux secrets partagés KEM
    et de deux nonces aléatoires.

    Schéma : HKDF-SHA256 (RFC 5869 / NIST SP 800-56C Rev. 3)
        IKM  = ss_e || ss_s     (secrets KEM)
        salt = r_c  || r_b      (nonces échangés)
        info = b'KEM-MQTT-v1'   (séparation de domaine applicatif)

    Retourne
    --------
    session_key (32 bytes)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=r_c + r_b,
        info=b'KEM-MQTT-v1',
    )
    session_key = hkdf.derive(ss_e + ss_s)
    return session_key


def derive_session_key_sig(pms, r_c, r_b):
    """
    Dérive la clé de session du schéma SIG.

    Schéma : HKDF-SHA256 (RFC 5869 / NIST SP 800-56C Rev. 3)
        IKM  = pms              (secret ML-KEM, encapsulé contre pk_kem)
        salt = r_c || r_b       (nonces échangés)
        info = b'SIG-MQTT-v1'   (séparation de domaine applicatif)

    Retourne
    --------
    session_key (32 bytes)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=r_c + r_b,
        info=b'SIG-MQTT-v1',
    )
    session_key = hkdf.derive(pms)
    return session_key


# Intégrité

# Labels du schéma SIG : tau_c et tau_b portent sur le même transcript,
# le label garantit que tau_b != tau_c (sinon un attaquant pourrait
# renvoyer tau_c au client comme s'il venait du broker).
# Transcript HMAC, à reproduire à l'identique en C :
#   tau_c = compute_hmac(K_sess, LABEL_CLIENT_FINISHED, r_c, r_b, pk_kem, sigma_s, ct)
#   tau_b = compute_hmac(K_sess, LABEL_BROKER_FINISHED, r_c, r_b, pk_kem, sigma_s, ct)
LABEL_CLIENT_FINISHED = b'SIG-MQTT client finished'
LABEL_BROKER_FINISHED = b'SIG-MQTT broker finished'


def compute_hmac(key, *messages):
    """
    Calcule HMAC-SHA256 sur la concaténation des messages fournis.
    """
    h = hmac_module.new(key, digestmod=hashlib.sha256)
    for msg in messages:
        h.update(msg)
    return h.digest()


def verify_hmac(key, expected_hmac, *messages):
    """
    Vérifie un HMAC-SHA256 en temps constant.
    Retourne True si valide, False sinon.
    """
    computed = compute_hmac(key, *messages)
    return hmac_module.compare_digest(computed, expected_hmac)


# Fonctions utilitaires

def random_nonce(size=32):
    """
    Génère un nonce aléatoire cryptographiquement sûr.
    """
    return os.urandom(size)


def get_key_sizes():
    """
    Retourne les tailles des paramètres ML-KEM-512 (FIPS 203).
    """
    return {
        'algorithm' : 'ML-KEM-512 (FIPS 203)',
        'pk_bytes'  : 800,
        'sk_bytes'  : 1632,
        'ct_bytes'  : 768,
        'ss_bytes'  : 32,
    }


def get_sig_sizes():
    """
    Retourne les tailles des paramètres ML-DSA-44 (FIPS 204).
    """
    return {
        'algorithm' : 'ML-DSA-44 (FIPS 204)',
        'pk_bytes'  : 1312,
        'sk_bytes'  : 2560,
        'sig_bytes' : 2420,
    }