# auth_sig_mqtt

Post-quantum broker authentication for MQTT 5.0 using a digital signature (ML-DSA-44) and an ephemeral key exchange (ML-KEM-512).

The broker side is a C plugin for Mosquitto 2.1.2; the client side is a Python client built on paho-mqtt.
The handshake runs inside the MQTT 5.0 Enhanced Authentication mechanism (`CONNECT` / `AUTH` / `CONNACK`), so the MQTT protocol itself is not modified.

The scheme is based on the signature-based authentication proposed by Samandari and Gritti [1].

## Overview

| Component | Role |
|---|---|
| ML-DSA-44 (FIPS 204) | Static identity of the broker; signature of the handshake (`sigma_s`) and of the broker certificate by the CA |
| ML-KEM-512 (FIPS 203) | Ephemeral key exchange (forward secrecy) |
| X.509 certificate | Binds the broker static key `pk_s` to its identity |
| HKDF-SHA256 | Derivation of the session key |
| HMAC-SHA256 | Handshake confirmation (`tau_c`, `tau_b`) |

## Software stack

| Component | Role |
|---|---|
| Eclipse Mosquitto 2.1.2 | MQTT broker; the authentication runs as a C plugin (`auth_sig.so`) |
| Eclipse Paho MQTT (Python, 2.1.0) | MQTT client, extended to send and receive `AUTH` packets |
| liboqs / liboqs-python | ML-DSA-44 and ML-KEM-512 implementations (broker and client) |
| OpenSSL 3.5 | CA, ML-DSA-44 signatures and X.509 certificates |
| Docker | Builds and runs the broker with the plugin |

## Handshake

```
CONNECT    client -> broker : r_c
AUTH 0x18  broker -> client : r_b || sigma_s || cert || pk_kem
AUTH 0x18  client -> broker : ct || tau_c
CONNACK    broker -> client : tau_b
```

```
sigma_s    = ML-DSA-44.Sign(sk_s, r_c || r_b || pk_kem)           broker
(ct, pms)  = ML-KEM.Encaps(pk_kem)                                client
K_sess = HKDF-SHA256(ikm = pms, salt = r_c || r_b, info = "SIG-MQTT-v1")
T      = r_c || r_b || pk_kem || sigma_s || ct
tau_c  = HMAC-SHA256(K_sess, "SIG-MQTT client finished" || T)
tau_b  = HMAC-SHA256(K_sess, "SIG-MQTT broker finished" || T)
```

The broker generates a fresh ML-KEM-512 key pair `(pk_kem, sk_kem)` for each connection and signs it, together with both nonces, with its static key `sk_s`.
The client verifies `cert` with the CA certificate, extracts `pk_s`, verifies `sigma_s`, then encapsulates a shared secret against `pk_kem`.
The broker is accepted only if `tau_b` is valid.

The signature proves, in every session, that the broker holds `sk_s` (as the CertificateVerify message does in TLS 1.3), and the ephemeral key exchange provides forward secrecy.
As in the original scheme [1], only the broker is authenticated; the client has no certified key.

## Repository structure

```
auth_sig_mqtt/
├── Broker_mqtt/
│   ├── plugin/
│   │   ├── Plugin_Mosquitto_sig.c   Mosquitto plugin (auth_sig.so)
│   │   └── primitives.c / .h        HKDF-SHA256, HMAC-SHA256
│   ├── config/mosquitto.conf
│   ├── keys/                        broker public key and certificate
│   ├── generate_broker_keys.py      generates the static key pair (pk_s, sk_s)
│   ├── Dockerfile
│   └── docker-compose.yml
├── ca/
│   ├── generate_certificate.sh      creates the CA and the broker certificate
│   └── ca.crt                       CA certificate (trust anchor)
└── client/
    ├── Client_mqtt_sig.py           MQTT 5 client with signature-based authentication
    ├── Primitives/                  ML-DSA, ML-KEM, HKDF, HMAC, certificate verification
    ├── keys/ca.crt
    └── requirements.txt
```

Private keys (`ca/ca.key`, `Broker_mqtt/keys/broker_sk_s.bin`) are not included in this repository. They are generated locally (see below).

## Requirements

Tested on Ubuntu (x86_64). You need:

- Git, Docker and Docker Compose
- Python 3.10 or later
- Build tools for liboqs: `gcc`, `cmake`, `ninja`, OpenSSL development headers

The broker runs in Docker: its image builds liboqs and the plugin itself.
The key generation script and the client run on the host, so liboqs and liboqs-python must be installed there.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Hajar-Boudfor/auth_sig_mqtt.git
cd auth_sig_mqtt
```

### 2. Install the build tools

```bash
sudo apt update
sudo apt install -y git cmake ninja-build gcc libssl-dev python3-venv python3-pip
```

### 3. Build and install liboqs

```bash
git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build
sudo cmake --build liboqs/build --target install
sudo ldconfig
```

Version 0.15.0 is the one used in the broker image (`Broker_mqtt/Dockerfile`).

### 4. Create a Python environment and install the packages

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r client/requirements.txt
```

Check that ML-DSA-44 and ML-KEM-512 are available:

```bash
python3 -c "import oqs; print('ML-DSA-44' in oqs.get_enabled_sig_mechanisms(), 'ML-KEM-512' in oqs.get_enabled_kem_mechanisms())"
```

The command must print `True True`.

## Usage

Commands are run from the root of the repository unless stated otherwise, with the Python environment activated (`source .venv/bin/activate`).

### 1. Generate the broker key pair (once)

```bash
cd Broker_mqtt
python3 generate_broker_keys.py
cd ..
```

This creates `Broker_mqtt/keys/broker_pk_s.bin` and `Broker_mqtt/keys/broker_sk_s.bin`. An existing secret key is never overwritten.

### 2. Create the CA and the broker certificate (once)

The script needs OpenSSL 3.5 or later (ML-DSA support). It can be run in a temporary container:

```bash
sudo docker run --rm \
    -v "$PWD/ca:/ca" -v "$PWD/Broker_mqtt/keys:/keys" \
    alpine:3.22 sh -c "apk add --no-cache openssl >/dev/null && sh /ca/generate_certificate.sh"
cp ca/ca.crt client/keys/ca.crt
```

This creates `ca/ca.key`, `ca/ca.crt` and `Broker_mqtt/keys/broker_cert.der`.
If you regenerate the CA, copy the new `ca.crt` to `client/keys/` again.

### 3. Start the broker

```bash
cd Broker_mqtt
sudo docker compose up --build -d
cd ..
```

The broker is reachable on port 1884 of the host (port 1883 inside the container) and only accepts clients that complete the signature-based handshake (`allow_anonymous false`).
To follow the broker logs:

```bash
sudo docker logs -f mosquitto-sig
```

### 4. Run the client

```bash
cd client
python3 Client_mqtt_sig.py
```

The client connects to `localhost:1884`. To use another broker address, edit `BROKER_HOST` and `BROKER_PORT` in `client/Client_mqtt_sig.py`.

### 5. Stop the broker

```bash
cd Broker_mqtt
sudo docker compose down
```

## Results

Mean over 100 handshakes, client and broker on the same host (the first handshake, which loads the libraries, is excluded):

| Metric | Value |
|---|---|
| Mean handshake time | 2.48 ms |

## Reference

[1] J. Samandari and C. Gritti, "Post-Quantum Authentication in the MQTT Protocol", *Journal of Cybersecurity and Privacy*, vol. 3, no. 3, 2023. doi:10.3390/jcp3030021

## Author

Hajar Boudfor
