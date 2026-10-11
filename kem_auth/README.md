# auth_kem_mqtt

Post-quantum broker authentication for MQTT 5.0 using a key encapsulation mechanism (ML-KEM-512).

The broker side is a C plugin for Mosquitto 2.1.2; the client side is a Python client built on paho-mqtt.
The handshake runs inside the MQTT 5.0 Enhanced Authentication mechanism (`CONNECT` / `AUTH` / `CONNACK`), so the MQTT protocol itself is not modified.

The scheme is based on the KEM-based authentication proposed by Samandari and Gritti [1].

## Overview

| Component | Role |
|---|---|
| ML-KEM-512 (FIPS 203) | Ephemeral key exchange and static encapsulation to the broker key |
| ML-DSA-44 (FIPS 204) | Signature of the broker certificate by the CA |
| X.509 certificate | Binds the broker static key `pk_s` to its identity |
| HKDF-SHA256 | Derivation of the session key |
| HMAC-SHA256 | Handshake confirmation (`tau_c`, `tau_b`) |

## Software stack

| Component | Role |
|---|---|
| Eclipse Mosquitto 2.1.2 | MQTT broker; the authentication runs as a C plugin (`auth_kem.so`) |
| Eclipse Paho MQTT (Python, 2.1.0) | MQTT client, extended to send and receive `AUTH` packets |
| liboqs / liboqs-python | ML-KEM-512 implementation (broker and client) |
| OpenSSL 3.5 | CA, ML-DSA-44 signatures and X.509 certificates |
| Docker | Builds and runs the broker with the plugin |

## Handshake

```
CONNECT    client -> broker : r_c || pk_e
AUTH 0x18  broker -> client : r_b || ct_e || cert
AUTH 0x18  client -> broker : ct_s || tau_c
CONNACK    broker -> client : tau_b
```

```
(ct_e, ss_e) = ML-KEM.Encaps(pk_e)                      broker
(ct_s, ss_s) = ML-KEM.Encaps(pk_s)                      client
K_sess = HKDF-SHA256(ikm = ss_e || ss_s, salt = r_c || r_b, info = "KEM-MQTT-v1")
T      = r_c || pk_e || r_b || ct_e || cert || ct_s
tau_c  = HMAC-SHA256(K_sess, "KEM-MQTT client finished" || T)
tau_b  = HMAC-SHA256(K_sess, "KEM-MQTT broker finished" || T)
```

The client verifies `cert` with the CA certificate, extracts `pk_s`, and accepts the broker only if `tau_b` is valid.
Only the holder of `sk_s` can decapsulate `ct_s` and therefore compute `K_sess`.


## Repository structure

```
auth_kem_mqtt/
├── broker/
│   ├── Pulgin_Mosquitto.c        Mosquitto plugin (auth_kem.so)
│   ├── primitives.c / .h         HKDF-SHA256, HMAC-SHA256
│   ├── generate_broker_keys.py   generates the static key pair (pk_s, sk_s)
│   ├── mosquitto.conf
│   └── Dockerfile
├── ca/
│   ├── generate_certificate.sh   creates the CA and the broker certificate
│   └── ca.crt                    CA certificate (trust anchor)
├── client/
│   ├── Client_mqtt.py            MQTT 5 client with KEM authentication
│   ├── Primitives/               ML-KEM, HKDF, HMAC, certificate verification
│   └── keys/ca.crt
├── keys/                         broker public key and certificate
└── docker-compose.yml
```

Private keys (`ca/ca.key`, `keys/broker_sk_s.bin`) are not included in this repository. They are generated locally (see below).

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
git clone https://github.com/Hajar-Boudfor/auth_kem_mqtt.git
cd auth_kem_mqtt
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

Version 0.15.0 is the one used in the broker image (`broker/Dockerfile`).

### 4. Create a Python environment and install the packages

```bash
python3 -m venv venv
source venv/bin/activate
pip install paho-mqtt==2.1.0 cryptography
pip install git+https://github.com/open-quantum-safe/liboqs-python.git
```

Check that ML-KEM-512 is available:

```bash
python3 -c "import oqs; print('ML-KEM-512' in oqs.get_enabled_kem_mechanisms())"
```

The command must print `True`.

## Usage

All commands are run from the root of the repository, with the Python environment activated (`source venv/bin/activate`).

### 1. Generate the broker key pair (once)

```bash
python3 broker/generate_broker_keys.py
```

This creates `keys/broker_pk_s.bin` and `keys/broker_sk_s.bin`. Existing keys are never overwritten.

### 2. Create the CA and the broker certificate (once)

The script needs OpenSSL 3.5 or later (ML-DSA support). It can be run in a temporary container:

```bash
sudo docker run --rm \
    -v "$PWD/ca:/ca" -v "$PWD/keys:/keys" \
    alpine:3.22 sh -c "apk add --no-cache openssl >/dev/null && sh /ca/generate_certificate.sh"
cp ca/ca.crt client/keys/ca.crt
```

This creates `ca/ca.key`, `ca/ca.crt` and `keys/broker_cert.der`.
If you regenerate the CA, copy the new `ca.crt` to `client/keys/` again.

### 3. Start the broker

```bash
sudo docker compose up --build -d
```

The broker listens on port 1883 and only accepts clients that complete the KEM handshake (`allow_anonymous false`).
To follow the broker logs:

```bash
sudo docker compose logs -f
```

### 4. Run the client

```bash
cd client
python3 Client_mqtt.py
```

The client connects to `localhost:1883`. To use another broker address, edit `BROKER_HOST` and `BROKER_PORT` in `client/Client_mqtt.py`.

### 5. Stop the broker

```bash
sudo docker compose down
```

## Results

Mean over 100 handshakes, client and broker on the same host (the first handshake, which loads the libraries, is excluded):

| Metric | Value |
|---|---|
| Mean handshake time | 2.01 ms |

## Reference

[1] J. Samandari and C. Gritti, "Post-Quantum Authentication in the MQTT Protocol", *Journal of Cybersecurity and Privacy*, vol. 3, no. 3, 2023. doi:10.3390/jcp3030021

## Author

Hajar Boudfor
