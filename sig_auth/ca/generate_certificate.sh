#!/bin/sh
# generate_certificate.sh — Phase 0, étapes 1 et 3 : CA + certificat X.509 ML-DSA
# =============================================================================
# À lancer UNE FOIS, APRÈS generate_broker_keys.py, dans un conteneur jetable
# qui fournit OpenSSL >= 3.5 (seule version qui connaît ML-DSA) :
#
#   cd ~/Mqtt_sign_auth
#   sudo docker run --rm \
#       -v "$PWD/ca:/ca" -v "$PWD/Broker_mqtt/keys:/keys" \
#       alpine:3.22 sh -c "apk add --no-cache openssl >/dev/null && sh /ca/generate_certificate.sh"
#
# Étape 1 : la CA génère sa paire ML-DSA-44 (ca.key, ca.crt)   → dossier ca/
# Étape 3 : la CA signe pk_s (broker_pk_s.bin, format brut liboqs)
#           → keys/broker_cert.der, envoyé par le broker à la place de pk_s
#
# sk_CA (ca.key) reste dans ca/ : jamais dans keys/, qui est monté dans le broker.
# Le client reçoit seulement ca.crt (son ancre de confiance).

set -e

OPENSSL="${OPENSSL:-openssl}"
CA_DIR="${CA_DIR:-/ca}"
KEYS_DIR="${KEYS_DIR:-/keys}"
TMP="$(mktemp -d)"

echo "[CERT] $($OPENSSL version)"

PK_RAW="$KEYS_DIR/broker_pk_s.bin"
if [ ! -f "$PK_RAW" ] || [ "$(wc -c < "$PK_RAW")" -ne 1312 ]; then
    echo "[CERT] $PK_RAW absent ou de mauvaise taille : lance d'abord generate_broker_keys.py"
    exit 1
fi

# ── Étape 1 : CA auto-hébergée (une seule fois) ──────────────
if [ -f "$CA_DIR/ca.key" ] && [ -f "$CA_DIR/ca.crt" ]; then
    echo "[CERT] CA existante réutilisée : $CA_DIR/ca.crt"
elif [ -f "$CA_DIR/ca.key" ] || [ -f "$CA_DIR/ca.crt" ]; then
    echo "[CERT] CA incomplète dans $CA_DIR : supprime ca.key et ca.crt, puis relance"
    exit 1
else
    # Générée dans un dossier temporaire, puis déplacée seulement si tout a réussi
    umask 077
    "$OPENSSL" genpkey -algorithm ML-DSA-44 -out "$TMP/ca.key"
    umask 022
    "$OPENSSL" req -x509 -new -key "$TMP/ca.key" \
        -subj "/CN=PQC-MQTT Test CA" -days 3650 \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$TMP/ca.crt"
    mv "$TMP/ca.key" "$TMP/ca.crt" "$CA_DIR/"
    echo "[CERT] CA créée : $CA_DIR/ca.key (secrète), $CA_DIR/ca.crt"
fi

# ── pk_s brute (liboqs) → SubjectPublicKeyInfo X.509 ─────────
# En-tête DER fixe pour ML-DSA-44 (OID 2.16.840.1.101.3.4.3.17, RFC 9881)
# puis les 1312 octets de pk_s.
{
    printf '\060\202\005\062\060\013\006\011\140\206\110\001\145\003\004\003\021\003\202\005\041\000'
    cat "$PK_RAW"
} > "$TMP/pk_s.der"
"$OPENSSL" pkey -pubin -inform DER -in "$TMP/pk_s.der" -out "$TMP/pk_s.pem"

# ── Étape 3 : la CA signe pk_s ───────────────────────────────
cat > "$TMP/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF

"$OPENSSL" x509 -new -subj "/CN=mosquitto-sig" \
    -force_pubkey "$TMP/pk_s.pem" \
    -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
    -days 365 -extfile "$TMP/ext.cnf" \
    -out "$TMP/broker_cert.pem"
"$OPENSSL" x509 -in "$TMP/broker_cert.pem" -outform DER -out "$KEYS_DIR/broker_cert.der"

# ── Vérifications ────────────────────────────────────────────
"$OPENSSL" verify -CAfile "$CA_DIR/ca.crt" "$TMP/broker_cert.pem"

"$OPENSSL" x509 -in "$TMP/broker_cert.pem" -noout -pubkey \
    | "$OPENSSL" pkey -pubin -outform DER -out "$TMP/cert_pk.der"
tail -c +23 "$TMP/cert_pk.der" > "$TMP/cert_pk.raw"
if cmp -s "$TMP/cert_pk.raw" "$PK_RAW"; then
    echo "[CERT] La clé du certificat est bien pk_s (broker_pk_s.bin)"
else
    echo "[CERT] ERREUR : la clé du certificat ne correspond pas à pk_s"
    exit 1
fi

echo "[CERT] Certificat du broker : $KEYS_DIR/broker_cert.der ($(wc -c < "$KEYS_DIR/broker_cert.der") octets)"
echo "[CERT] Ancre du client      : $CA_DIR/ca.crt  → à copier dans client/keys/"
rm -rf "$TMP"
