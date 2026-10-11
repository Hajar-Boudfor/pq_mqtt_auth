"""
Client_mqtt.py — Dispositif IoT avec authentification post-quantique ML-KEM-512
================================================================================
Thèse — Hajar Boudfor — FST Rabat, 2025-2026
Superviseur : Pr. El Souidi
Référence   : Samandari & Gritti (2023), DOI:10.3390/jcp3030021

Handshake KEM-MQTT5 (Enhanced Authentication) :
  1. CLIENT_HELLO    → CONNECT   : AuthData = r_c || pk_e          (832 bytes)
  2. BROKER_HELLO    ← AUTH 0x18 : AuthData = r_b || ct_e || cert   (800 + cert bytes)
  3. CLIENT_FINISHED → AUTH 0x18 : AuthData = ct_s || tau_c         (800 bytes)
  4. CONNACK         ← broker    : AuthData = tau_b                 (32 bytes)

  K_sess = HKDF-SHA256(IKM = ss_e || ss_s, salt = r_c || r_b, info = "KEM-MQTT-v1")
  T      = r_c || pk_e || r_b || ct_e || cert || ct_s
  cert   = certificat X.509 de pk_s (ML-KEM-512) signé par la CA (ML-DSA-44)
  tau_c  = HMAC(K_sess, "KEM-MQTT client finished" || T)
  tau_b  = HMAC(K_sess, "KEM-MQTT broker finished" || T)

Phase 0 : le client ne connaît que ca.crt (keys/ca.crt), l'ancre de confiance.
Il vérifie cert avec la clé de la CA, puis en extrait pk_s.
Le broker est authentifié quand tau_b est valide : seul le détenteur de sk_s
a pu décapsuler ct_s et donc calculer K_sess.

Note technique : paho-mqtt 2.1.0 ne gère pas le paquet AUTH (0xF0).
La classe PQCClient ajoute la réception et l'envoi de AUTH, sans modifier
la bibliothèque paho (même classe que le client SIG).
"""

import hmac
import os
import time
import oqs
import paho.mqtt.client as mqtt
from paho.mqtt.enums import MQTTErrorCode
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.reasoncodes import ReasonCode

# Primitives cryptographiques (ML-KEM-512, HKDF-SHA256, HMAC-SHA256)
from Primitives.Primitives import (
    kem_decapsulate,
    kem_encapsulate,
    derive_session_key,
    compute_hmac,
)
from Primitives.Certificate import load_ca, verify_broker_certificate

# ── Tailles ML-KEM-512 (FIPS 203) ─────────────────────────────
PK_SIZE    = 800   # pk_e, pk_s
CT_SIZE    = 768   # ct_e, ct_s
NONCE_SIZE = 32    # r_c, r_b
HMAC_SIZE  = 32    # tau_c, tau_b
# BROKER_HELLO = r_b || ct_e || cert : seule la taille de cert varie
BROKER_HELLO_MIN_SIZE = NONCE_SIZE + CT_SIZE          # 800 + cert
CERT_MAX_SIZE = 8192        # même limite que CERT_MAX_LEN dans le plugin

# Labels HMAC : identiques au plugin C (24 octets)
LABEL_CLIENT_FINISHED = b"KEM-MQTT client finished"
LABEL_BROKER_FINISHED = b"KEM-MQTT broker finished"

# ── Configuration ─────────────────────────────────────────────
BROKER_HOST = "localhost"
BROKER_PORT = 1883          # conteneur mosquitto-kem
AUTH_METHOD = "KEM"
BROKER_CN   = "mosquitto-kem"   # nom attendu dans le certificat (CN)
CA_CERT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "keys", "ca.crt")

AUTH_PACKET = 0xF0          # type de paquet AUTH (MQTT5 §3.15)
CONTINUE_AUTHENTICATION = 0x18

# ── État du handshake (partagé entre on_auth et on_connect) ───
session = {
    "kem"        : None,   # objet liboqs (garde sk_e)
    "pk_e"       : None,
    "r_c"        : None,
    "K_sess"     : None,
    "transcript" : None,   # (r_c, pk_e, r_b, ct_e, cert, ct_s) pour tau_b
    "t_start"    : None,
}


# ─────────────────────────────────────────────────────────────
# Client paho avec support du paquet AUTH
# ─────────────────────────────────────────────────────────────
class PQCClient(mqtt.Client):
    """paho-mqtt Client + réception/envoi du paquet AUTH (0xF0)."""

    on_auth = None

    def _packet_handle(self):
        cmd = self._in_packet['command'] & 0xF0
        if cmd == AUTH_PACKET and self._protocol == mqtt.MQTTv5:
            return self._handle_auth()
        return super()._packet_handle()

    def _handle_auth(self):
        packet = self._in_packet['packet']
        properties = Properties(PacketTypes.AUTH)
        if len(packet) == 0:
            reason = ReasonCode(PacketTypes.AUTH, identifier=0x00)
        else:
            reason = ReasonCode(PacketTypes.AUTH, identifier=packet[0])
            if len(packet) > 1:
                properties.unpack(packet[1:])
        if self.on_auth:
            self.on_auth(self, self._userdata, reason, properties)
        return MQTTErrorCode.MQTT_ERR_SUCCESS

    def send_auth(self, reason_code, properties):
        """Envoie un paquet AUTH via la file d'envoi de paho."""
        payload = bytes([reason_code]) + properties.pack()
        packet = bytearray([AUTH_PACKET])
        self._pack_remaining_length(packet, len(payload))
        packet.extend(payload)
        return self._packet_queue(AUTH_PACKET, bytes(packet), 0, 0)


# ─────────────────────────────────────────────────────────────
# PHASE 3 — AUTH reçu : BROKER_HELLO → CLIENT_FINISHED
# ─────────────────────────────────────────────────────────────
def on_auth(client, userdata, reason_code, properties):
    print(f"\n[on_auth] AUTH reçu — reason_code={reason_code}")
    try:
        r_c, pk_e = session["r_c"], session["pk_e"]
        raw = bytes(getattr(properties, "AuthenticationData", b""))

        # ── Contrôle de longueur avant tout découpage ─────────
        cert_len = len(raw) - BROKER_HELLO_MIN_SIZE
        if not 0 < cert_len <= CERT_MAX_SIZE:
            raise ValueError(f"BROKER_HELLO de {len(raw)} bytes : taille invalide")

        # ── Parsing r_b || ct_e || cert ──────────────────────
        # r_b et ct_e ont une taille fixe : cert est tout ce qui suit
        r_b      = raw[:NONCE_SIZE]
        ct_e     = raw[NONCE_SIZE:NONCE_SIZE + CT_SIZE]
        cert_der = raw[NONCE_SIZE + CT_SIZE:]

        print(f"[BROKER_HELLO] r_b  : {r_b.hex()[:16]}... ({len(r_b)} bytes)")
        print(f"[BROKER_HELLO] ct_e : {ct_e.hex()[:16]}... ({len(ct_e)} bytes)")
        print(f"[BROKER_HELLO] cert : {cert_der.hex()[:16]}... ({len(cert_der)} bytes)")

        # ── Vérification du certificat avec la clé de la CA ───
        pk_s = verify_broker_certificate(cert_der, CA_CERT, PK_CA, BROKER_CN)
        print(f"[VERIFY] certificat valide (CA → {BROKER_CN}), pk_s extraite")

        # ── Décapsulation éphémère : ct_e + sk_e → ss_e ───────
        ss_e = kem_decapsulate(ct_e, session["kem"].export_secret_key())

        # ── Encapsulation statique : pk_s → ct_s, ss_s ────────
        ct_s, ss_s = kem_encapsulate(pk_s)
        print(f"[ENCAPS] ct_s       : {ct_s.hex()[:16]}... ({len(ct_s)} bytes)")

        # ── Dérivation K_sess (HKDF-SHA256) ───────────────────
        K_sess = derive_session_key(ss_e, ss_s, r_c, r_b)
        print(f"[HKDF] K_sess       : {K_sess.hex()[:16]}...")

        # ── Preuve client tau_c sur le transcript complet ─────
        transcript = (r_c, pk_e, r_b, ct_e, cert_der, ct_s)
        tau_c = compute_hmac(K_sess, LABEL_CLIENT_FINISHED, *transcript)
        print(f"[HMAC] tau_c        : {tau_c.hex()[:16]}...")

        session["K_sess"] = K_sess
        session["transcript"] = transcript

        # ── CLIENT_FINISHED : AUTH 0x18, AuthData = ct_s || tau_c
        resp_props = Properties(PacketTypes.AUTH)
        resp_props.AuthenticationMethod = AUTH_METHOD
        resp_props.AuthenticationData   = ct_s + tau_c
        client.send_auth(CONTINUE_AUTHENTICATION, resp_props)
        print(f"[CLIENT_FINISHED] AUTH envoyé (AuthData {len(ct_s) + len(tau_c)} bytes)")

    except Exception as e:
        print(f"[ÉCHEC PHASE 3] {type(e).__name__}: {e} — déconnexion")
        client.disconnect()


# ─────────────────────────────────────────────────────────────
# CONNACK reçu : vérification de tau_b (authentification du broker)
# ─────────────────────────────────────────────────────────────
def on_connect(client, userdata, flags, reason_code, properties):
    print(f"\n[on_connect] reason_code = {reason_code}")
    if reason_code != 0:
        print(f" Refusé par le broker : {reason_code}")
        client.disconnect()
        return

    tau_b = bytes(getattr(properties, "AuthenticationData", b""))
    K_sess = session["K_sess"]
    if K_sess is None or len(tau_b) != HMAC_SIZE:
        print(" tau_b absent — broker non authentifié, déconnexion")
        client.disconnect()
        return
    expected = compute_hmac(K_sess, LABEL_BROKER_FINISHED, *session["transcript"])
    if not hmac.compare_digest(expected, tau_b):
        print(" tau_b invalide — broker non authentifié, déconnexion")
        client.disconnect()
        return

    t_ms = (time.perf_counter() - session["t_start"]) * 1000
    print("[VERIFY] tau_b valide — Broker authenticated")
    print(f" Connecté MQTT v5 — handshake KEM terminé en {t_ms:.2f} ms")
    client.subscribe("pqc/sensor", qos=1)


def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    print(f"[on_disconnect] reason_code = {reason_code}")


def on_message(client, userdata, msg):
    print(f"[MESSAGE] topic={msg.topic} | payload={msg.payload.decode()}")


# ─────────────────────────────────────────────────────────────
# Ancre de confiance : certificat de la CA, connu à l'avance (Phase 0)
# ─────────────────────────────────────────────────────────────
try:
    CA_CERT, PK_CA = load_ca(CA_CERT_PATH)
except (OSError, ValueError) as e:
    raise SystemExit(f"{CA_CERT_PATH} : {e}")


if __name__ == "__main__":
    # ─────────────────────────────────────────────────────────
    # PHASE 1 — CLIENT_HELLO : clé éphémère et nonce
    # ─────────────────────────────────────────────────────────
    session["kem"]  = oqs.KeyEncapsulation("ML-KEM-512")
    session["pk_e"] = session["kem"].generate_keypair()
    session["r_c"]  = os.urandom(NONCE_SIZE)

    print("=" * 55)
    print("  PQC-MQTT Client — ML-KEM-512 (KEM)")
    print("  Hajar Boudfor — FST Rabat, 2025-2026")
    print("=" * 55)
    print(f"[CLIENT_HELLO] pk_e : {session['pk_e'].hex()[:16]}... ({len(session['pk_e'])} bytes)")
    print(f"[CLIENT_HELLO] r_c  : {session['r_c'].hex()[:16]}... ({len(session['r_c'])} bytes)")

    connect_props = Properties(PacketTypes.CONNECT)
    connect_props.AuthenticationMethod = AUTH_METHOD
    connect_props.AuthenticationData   = session["r_c"] + session["pk_e"]   # 832 bytes

    client = PQCClient(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        protocol=mqtt.MQTTv5,
    )
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_auth       = on_auth
    client.on_message    = on_message

    print(f"\n[CONNECT] → {BROKER_HOST}:{BROKER_PORT}")
    session["t_start"] = time.perf_counter()
    client.connect(BROKER_HOST, BROKER_PORT, properties=connect_props)
    client.loop_forever()
