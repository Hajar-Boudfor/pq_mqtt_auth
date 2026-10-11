"""
generate_broker_keys.py — Phase 0 (hors ligne) du schéma KEM

Génère UNE SEULE FOIS la paire statique ML-KEM-512 du broker :
  keys/broker_pk_s.bin  (800 octets)   
  keys/broker_sk_s.bin  (1632 octets)  

Usage (venv actif, depuis la racine du projet) :
  python3 broker/generate_broker_keys.py


"""

import os
import sys
import oqs

ALG = "ML-KEM-512"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(ROOT, "keys")
PK_PATH = os.path.join(KEYS_DIR, "broker_pk_s.bin")
SK_PATH = os.path.join(KEYS_DIR, "broker_sk_s.bin")


def main():
    if os.path.exists(PK_PATH) or os.path.exists(SK_PATH):
        sys.exit(f"[KEYS] Des clés existent déjà dans {KEYS_DIR} : rien n'est écrasé.")

    os.makedirs(KEYS_DIR, exist_ok=True)
    with oqs.KeyEncapsulation(ALG) as kem:
        pk_s = kem.generate_keypair()
        sk_s = kem.export_secret_key()

        # Vérification de la paire avant écriture
        ct, ss1 = kem.encap_secret(pk_s)
        ss2 = kem.decap_secret(ct)
        if ss1 != ss2:
            sys.exit("[KEYS] Paire invalide : rien n'est écrit.")

    with open(PK_PATH, "wb") as f:
        f.write(pk_s)
    # Clé secrète : créée directement avec les droits 0600
    fd = os.open(SK_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(sk_s)

    print(f"[KEYS] {ALG} : pk_s ({len(pk_s)} octets) → {PK_PATH}")
    print(f"[KEYS] {ALG} : sk_s ({len(sk_s)} octets) → {SK_PATH}  (mode 0600)")
    print("[KEYS] Copie broker_pk_s.bin dans client/keys/ (pinning)")


if __name__ == "__main__":
    main()
