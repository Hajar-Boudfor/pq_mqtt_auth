"""
Certificate.py — Vérification du certificat X.509 du broker (schéma KEM)
========================================================================
Phase 0 : la CA (auto-hébergée, clé ML-DSA-44) a signé pk_s, la clé
ML-KEM-512 statique du broker → broker_cert.der.
Le client ne connaît à l'avance que ca.crt (son ancre de confiance).

Pendant le handshake, le client reçoit cert[pk_s] dans le BROKER_HELLO et :
  1. vérifie la signature de la CA sur le certificat (ML-DSA-44, liboqs) ;
  2. vérifie l'émetteur, le nom du broker et la période de validité ;
  3. extrait pk_s (ML-KEM-512) du certificat → sert ensuite à Encaps(pk_s).


"""

import datetime
import oqs
from cryptography import x509
from cryptography.x509.oid import NameOID

# Algorithme de signature de la CA
ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17"     # RFC 9881
ML_DSA_44_PK_BYTES = 1312
# En-tête DER du SubjectPublicKeyInfo ML-DSA-44 (22 octets), suivi de pk (1312 octets)
SPKI_PREFIX_ML_DSA_44 = bytes.fromhex("30820532300b06096086480165030403110382052100")

# Algorithme de la clé du broker
ML_KEM_512_OID = "2.16.840.1.101.3.4.4.1"
ML_KEM_512_PK_BYTES = 800
# En-tête DER du SubjectPublicKeyInfo ML-KEM-512 (22 octets), suivi de pk (800 octets)
SPKI_PREFIX_ML_KEM_512 = bytes.fromhex("30820332300b06096086480165030404010382032100")


def _extract_pk(cert, oid, prefix, pk_len):
    """Extrait la clé publique brute du SubjectPublicKeyInfo d'un certificat."""
    if cert.public_key_algorithm_oid.dotted_string != oid:
        raise ValueError(f"clé du certificat inattendue "
                         f"({cert.public_key_algorithm_oid.dotted_string})")
    tbs = cert.tbs_certificate_bytes
    if tbs.count(prefix) != 1:
        raise ValueError("SubjectPublicKeyInfo introuvable")
    start = tbs.index(prefix) + len(prefix)
    pk = tbs[start:start + pk_len]
    if len(pk) != pk_len:
        raise ValueError("clé publique tronquée")
    return pk


def _check_signature(cert, pk_ca):
    """Vérifie la signature ML-DSA-44 de la CA sur tbs_certificate_bytes."""
    if cert.signature_algorithm_oid.dotted_string != ML_DSA_44_OID:
        raise ValueError("certificat non signé en ML-DSA-44")
    with oqs.Signature("ML-DSA-44") as verifier:
        if not verifier.verify(cert.tbs_certificate_bytes, cert.signature, pk_ca):
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
    pk_ca = _extract_pk(ca_cert, ML_DSA_44_OID, SPKI_PREFIX_ML_DSA_44, ML_DSA_44_PK_BYTES)
    _check_signature(ca_cert, pk_ca)          # auto-signée
    _check_validity(ca_cert)
    return ca_cert, pk_ca


def verify_broker_certificate(cert_der, ca_cert, pk_ca, expected_cn):
    """
    Vérifie cert[pk_s] reçu du broker et retourne pk_s (ML-KEM-512, 800 octets).
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

    return _extract_pk(cert, ML_KEM_512_OID, SPKI_PREFIX_ML_KEM_512, ML_KEM_512_PK_BYTES)
