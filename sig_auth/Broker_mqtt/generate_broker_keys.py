"""
generate_broker_keys.py — Phase 0 (hors ligne) du schéma SIG-MQTT

Génère UNE SEULE FOIS la paire de clés statique ML-DSA-44 du broker
(FIPS 204) et l'écrit en binaire brut :

  broker_pk_s.bin   
  broker_sk_s.bin  

Usage (depuis Broker_mqtt/) :
  python3 generate_broker_keys.py            
  python3 generate_broker_keys.py mon_dossier
"""

import os
import sys
import oqs

SIG_ALGORITHM = 'ML-DSA-44'


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else 'keys'
    os.makedirs(out_dir, exist_ok=True)

    pk_path = os.path.join(out_dir, 'broker_pk_s.bin')
    sk_path = os.path.join(out_dir, 'broker_sk_s.bin')

    if os.path.exists(sk_path):
        print(f"[KEYGEN] {sk_path} existe déjà : supprime-le d'abord "
              "si tu veux vraiment changer l'identité du broker.")
        sys.exit(1)

    with oqs.Signature(SIG_ALGORITHM) as sig:
        pk_s = sig.generate_keypair()
        sk_s = sig.export_secret_key()

    with open(pk_path, 'wb') as f:
        f.write(pk_s)

    # Clé secrète : lisible uniquement par le propriétaire (0600)
    fd = os.open(sk_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(sk_s)

    print(f"[KEYGEN] {SIG_ALGORITHM}")
    print(f"[KEYGEN] pk_s → {pk_path} ({len(pk_s)} bytes)")
    print(f"[KEYGEN] sk_s → {sk_path} ({len(sk_s)} bytes)")


if __name__ == '__main__':
    main()
