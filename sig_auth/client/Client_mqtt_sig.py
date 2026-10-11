"""
Client_mqtt_sig.py — IoT device with ML-DSA-44 post-quantum authentication

Thèse — Hajar Boudfor — FST Rabat
Superviseur : Pr. El Souidi
Référence   : Samandari & Gritti (2023), DOI:10.3390/jcp3030021

Handshake SIG-MQTT5 (Enhanced Authentication) :
  1. CLIENT_HELLO    → CONNECT   : AuthData = r_c                               (32 bytes)
  2. BROKER_HELLO    ← AUTH 0x18 : AuthData = r_b || sigma_s || cert || pk_kem  (~7257 bytes)
  3. CLIENT_FINISHED → AUTH 0x18 : AuthData = ct || tau_c                       (800 bytes)
  4. CONNACK         ← broker    : AuthData = tau_b                             (32 bytes)

  sigma_s = ML-DSA-44.Sign(sk_s, r_c || r_b || pk_kem)
  K_sess  = HKDF-SHA256(IKM = pms, salt = r_c || r_b, info = "SIG-MQTT-v1")
  tau_c   = HMAC(K_sess, "SIG-MQTT client finished" || r_c || r_b || pk_kem || sigma_s || ct)
  tau_b   = HMAC(K_sess, "SIG-MQTT broker finished" || r_c || r_b || pk_kem || sigma_s || ct)

  cert    = certificat X.509 de pk_s signé par la CA (ML-DSA-44, DER, taille variable)

Phase 0 : le client ne connaît que ca.crt (keys/ca.crt), l'ancre de confiance.
Il vérifie cert avec la clé de la CA, puis en extrait pk_s pour vérifier sigma_s.


"""

import os
import time
import paho.mqtt.client as mqtt
from paho.mqtt.enums import MQTTErrorCode
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.reasoncodes import ReasonCode

# Primitives cryptographiques (ML-DSA-44, ML-KEM-512, HKDF-SHA256, HMAC-SHA256)
from Primitives.Primitives import (
    random_nonce,
    sig_verify,
    sig_transcript,
    kem_encapsulate,
    derive_session_key_sig,
    compute_hmac,
    verify_hmac,
    LABEL_CLIENT_FINISHED,
    LABEL_BROKER_FINISHED,
)
from Primitives.Certificate import load_ca, verify_broker_certificate


NONCE_SIZE  = 32     # r_c, r_b
SIG_SIZE    = 2420   # sigma_s   (ML-DSA-44)
PK_S_SIZE   = 1312   # pk_s      (ML-DSA-44)
PK_KEM_SIZE = 800    # pk_kem    (ML-KEM-512)
CT_SIZE     = 768    # ct        (ML-KEM-512)
HMAC_SIZE   = 32     # tau_c, tau_b
# BROKER_HELLO = r_b || sigma_s || cert || pk_kem : seule la taille de cert varie
BROKER_HELLO_MIN_SIZE = NONCE_SIZE + SIG_SIZE + PK_KEM_SIZE          # 3252 + cert
CERT_MAX_SIZE = 8192        # même limite que CERT_MAX_LEN dans le plugin

#  Configuration 
BROKER_HOST = "localhost"
BROKER_PORT = 1884          # conteneur mosquitto-sig
AUTH_METHOD = "SIG"
BROKER_CN   = "mosquitto-sig"   # nom attendu dans le certificat (CN)
CA_CERT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "keys", "ca.crt")

AUTH_PACKET = 0xF0          # type de paquet AUTH (MQTT5 §3.15)
CONTINUE_AUTHENTICATION = 0x18

# ── État du handshake (partagé entre on_auth et on_connect) ───
session = {
    "r_c"        : None,
    "K_sess"     : None,
    "transcript" : None,   # (r_c, r_b, pk_kem, sigma_s, ct) pour tau_b
    "t_start"    : None,
}


# Client paho avec support du paquet AUTH

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
            # Longueur restante 0 : reason code 0x00, pas de propriétés
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



# PHASE 3 — AUTH reçu : BROKER_HELLO → CLIENT_FINISHED

def on_auth(client, userdata, reason_code, properties):
    print(f"\n[on_auth] AUTH reçu — reason_code={reason_code}")
    try:
        r_c = session["r_c"]
        raw = bytes(getattr(properties, "AuthenticationData", b""))

        # ── Contrôle de longueur avant tout découpage ─────────
        cert_len = len(raw) - BROKER_HELLO_MIN_SIZE
        if not 0 < cert_len <= CERT_MAX_SIZE:
            raise ValueError(f"BROKER_HELLO de {len(raw)} bytes : taille invalide")

        # ── Parsing r_b || sigma_s || cert || pk_kem ─────────
        # r_b, sigma_s et pk_kem ont une taille fixe : cert est ce qui reste au milieu
        o1 = NONCE_SIZE
        o2 = o1 + SIG_SIZE
        r_b      = raw[:o1]
        sigma_s  = raw[o1:o2]
        cert_der = raw[o2:-PK_KEM_SIZE]
        pk_kem   = raw[-PK_KEM_SIZE:]

        print(f"[BROKER_HELLO] r_b     : {r_b.hex()[:16]}... ({len(r_b)} bytes)")
        print(f"[BROKER_HELLO] sigma_s : {sigma_s.hex()[:16]}... ({len(sigma_s)} bytes)")
        print(f"[BROKER_HELLO] cert    : {cert_der.hex()[:16]}... ({len(cert_der)} bytes)")
        print(f"[BROKER_HELLO] pk_kem  : {pk_kem.hex()[:16]}... ({len(pk_kem)} bytes)")

        # ── Vérification du certificat avec la clé de la CA ───
        pk_s = verify_broker_certificate(cert_der, CA_CERT, PK_CA, BROKER_CN)
        print(f"[VERIFY] certificat valide (CA → {BROKER_CN}), pk_s extraite")

        # ── Vérification de sigma_s avec pk_s du certificat ───
        if not sig_verify(sig_transcript(r_c, r_b, pk_kem), sigma_s, pk_s):
            raise ValueError("signature sigma_s invalide")
        print("[VERIFY] sigma_s valide — Broker Identity Authenticated")

        # ── Encapsulation contre la clé KEM éphémère ──────────
        ct, pms = kem_encapsulate(pk_kem)
        print(f"[ENCAPS] ct          : {ct.hex()[:16]}... ({len(ct)} bytes)")

        # ── Dérivation K_sess (HKDF-SHA256) ───────────────────
        K_sess = derive_session_key_sig(pms, r_c, r_b)
        print(f"[HKDF] K_sess        : {K_sess.hex()[:16]}...")

        # ── Preuve client tau_c ───────────────────────────────
        tau_c = compute_hmac(K_sess, LABEL_CLIENT_FINISHED,
                             r_c, r_b, pk_kem, sigma_s, ct)
        print(f"[HMAC] tau_c         : {tau_c.hex()[:16]}...")

        session["K_sess"] = K_sess
        session["transcript"] = (r_c, r_b, pk_kem, sigma_s, ct)

        # ── CLIENT_FINISHED : AUTH 0x18, AuthData = ct || tau_c
        resp_props = Properties(PacketTypes.AUTH)
        resp_props.AuthenticationMethod = AUTH_METHOD
        resp_props.AuthenticationData   = ct + tau_c
        client.send_auth(CONTINUE_AUTHENTICATION, resp_props)
        print(f"[CLIENT_FINISHED] AUTH envoyé (AuthData {len(ct) + len(tau_c)} bytes)")

    except Exception as e:
        print(f"[ÉCHEC PHASE 3] {type(e).__name__}: {e} — déconnexion")
        client.disconnect()



# CONNACK reçu : vérification de tau_b (confirmation de clé)

def on_connect(client, userdata, flags, reason_code, properties):
    print(f"\n[on_connect] reason_code = {reason_code}")
    if reason_code != 0:
        print(f" Refusé par le broker : {reason_code}")
        client.disconnect()
        return

    tau_b = bytes(getattr(properties, "AuthenticationData", b""))
    K_sess = session["K_sess"]

    if K_sess is None or len(tau_b) != HMAC_SIZE or not verify_hmac(
            K_sess, tau_b, LABEL_BROKER_FINISHED, *session["transcript"]):
        print(" tau_b absent ou invalide — déconnexion")
        client.disconnect()
        return

    t_ms = (time.perf_counter() - session["t_start"]) * 1000
    print(f"[VERIFY] tau_b valide — Key Confirmed")
    print(f" Connecté MQTT v5 — handshake SIG terminé en {t_ms:.2f} ms")
    client.subscribe("pqc/sensor", qos=1)


def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    print(f"[on_disconnect] reason_code = {reason_code}")


def on_message(client, userdata, msg):
    print(f"[MESSAGE] topic={msg.topic} | payload={msg.payload.decode()}")



# Ancre de confiance : certificat de la CA, connu à l'avance (Phase 0)

try:
    CA_CERT, PK_CA = load_ca(CA_CERT_PATH)
except (OSError, ValueError) as e:
    raise SystemExit(f"{CA_CERT_PATH} : {e}")


if __name__ == "__main__":

    # PHASE 1 — CLIENT_HELLO

    session["r_c"] = random_nonce(NONCE_SIZE)

    print("=" * 55)
    print("  PQC-MQTT Client — ML-DSA-44 + ML-KEM-512 (SIG)")
    print("  Hajar Boudfor — FST Rabat, 2025-2026")
    print("=" * 55)
    print(f"[CLIENT_HELLO] r_c : {session['r_c'].hex()[:16]}... "
          f"({len(session['r_c'])} bytes)")

    connect_props = Properties(PacketTypes.CONNECT)
    connect_props.AuthenticationMethod = AUTH_METHOD
    connect_props.AuthenticationData   = session["r_c"]

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
