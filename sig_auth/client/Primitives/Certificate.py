"""
Certificate.py — Vérification du certificat X.509 ML-DSA-44 du broker
=====================================================================
Phase 0 : la CA (auto-hébergée) a signé pk_s → broker_cert.der.
Le client ne connaît à l'avance que ca.crt (son ancre de confiance).

Pendant le handshake, le client reçoit cert[pk_s] dans le BROKER_HELLO et :
  1. vérifie la signature de la CA sur le certificat (ML-DSA-44, liboqs) ;
  2. vérifie l'émetteur, le nom du broker et la période de validité ;
  3. extrait pk_s du certificat → sert ensuite à vérifier sigma_s.

Pourquoi liboqs et pas seulement `cryptography` ?
  `cryptography` sait lire (parser) un certificat ML-DSA, mais pas encore
  vérifier sa signature : cert.public_key() lève « Unknown key type ».
  On lit donc les champs avec `cryptography` et on vérifie avec liboqs.
  La signature X.509 porte sur tbs_certificate_bytes (RFC 5280, §4.1.1.3).
"""

import datetime
import oqs
from cryptography import x509
from cryptography.x509.oid import NameOID

ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17"     # RFC 9881
ML_DSA_44_PK_BYTES = 1312

# En-tête DER du SubjectPublicKeyInfo ML-DSA-44 (22 octets), suivi de pk (1312 octets)
#   30 82 05 32              SEQUENCE (1330 octets)
#     30 0b 06 09 <OID>      AlgorithmIdentifier = ML-DSA-44
#     03 82 05 21 00         BIT STRING (1313 octets, 0 bit inutilisé)
SPKI_PREFIX_ML_DSA_44 = bytes.fromhex("30820532300b06096086480165030403110382052100")


def _extract_ml_dsa_44_pk(cert):
    """Extrait la clé publique brute (1312 octets) d'un certificat ML-DSA-44."""
    if cert.public_key_algorithm_oid.dotted_string != ML_DSA_44_OID:
        raise ValueError("la clé du certificat n'est pas ML-DSA-44")
    tbs = cert.tbs_certificate_bytes
    if tbs.count(SPKI_PREFIX_ML_DSA_44) != 1:
        raise ValueError("SubjectPublicKeyInfo ML-DSA-44 introuvable")
    start = tbs.index(SPKI_PREFIX_ML_DSA_44) + len(SPKI_PREFIX_ML_DSA_44)
    pk = tbs[start:start + ML_DSA_44_PK_BYTES]
    if len(pk) != ML_DSA_44_PK_BYTES:
        raise ValueError("clé publique tronquée")
    return pk


def _check_signature(cert, pk_issuer):
    """Vérifie la signature ML-DSA-44 de l'émetteur sur tbs_certificate_bytes."""
    if cert.signature_algorithm_oid.dotted_string != ML_DSA_44_OID:
        raise ValueError("certificat non signé en ML-DSA-44")
    with oqs.Signature("ML-DSA-44") as verifier:
        if not verifier.verify(cert.tbs_certificate_bytes, cert.signature, pk_issuer):
            raise ValueError("signature de la CA invalide")


def _check_validity(cert):
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValueError(f"certificat hors période de validité "
                         f"({cert.not_valid_before_utc} → {cert.not_valid_after_utc})")


def load_ca(path):
    """Charge ca.crt (PEM), vérifie son auto-signature, retourne (ca_cert, pk_CA)."""
    with open(path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    pk_ca = _extract_ml_dsa_44_pk(ca_cert)
    _check_signature(ca_cert, pk_ca)          # auto-signée
    _check_validity(ca_cert)
    return ca_cert, pk_ca


def verify_broker_certificate(cert_der, ca_cert, pk_ca, expected_cn):
    """
    Vérifie cert[pk_s] reçu du broker et retourne pk_s (1312 octets).
    Lève ValueError si une vérification échoue.
    """
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except ValueError as e:
        raise ValueError(f"certificat illisible : {e}")

    if cert.issuer != ca_cert.subject:
        raise ValueError("certificat non émis par notre CA")
    _check_signature(cert, pk_ca)
    _check_validity(cert)

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn or cn[0].value != expected_cn:
        raise ValueError(f"nom du broker inattendu : {cn[0].value if cn else None}")

    return _extract_ml_dsa_44_pk(cert)
