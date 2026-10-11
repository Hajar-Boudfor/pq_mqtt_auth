# Broker MQTT du schéma SIG (ML-DSA-44 + ML-KEM-512)
# Mêmes versions que le conteneur KEM : seul le plugin change.

FROM alpine:3.19 AS builder

# cjson-dev est nécessaire : mosquitto.h (2.1.x) inclut <cjson/cJSON.h>
RUN apk add --no-cache \
    build-base cmake git \
    openssl-dev cjson-dev

# En-têtes de Mosquitto (même version que l'image d'exécution)
RUN git clone --depth 1 --branch v2.1.2 \
    https://github.com/eclipse/mosquitto.git /opt/mosquitto-src

RUN git clone --depth 1 --branch 0.15.0 \
    https://github.com/open-quantum-safe/liboqs.git /opt/liboqs \
    && cd /opt/liboqs && mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON .. \
    && make -j$(nproc) && make install

WORKDIR /build
COPY ./plugin /build/

RUN gcc -I/usr/local/include \
        -I/opt/mosquitto-src/include \
        -I. -fPIC -shared \
        Plugin_Mosquitto_sig.c primitives.c \
        -o auth_sig.so -loqs -lssl -lcrypto

# Version fixée (et non "latest") pour que KEM et SIG tournent sur le même Mosquitto
FROM eclipse-mosquitto:2.1.2-alpine
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
RUN mkdir -p /mosquitto/plugins /mosquitto/keys
COPY --from=builder /build/auth_sig.so /mosquitto/plugins/auth_sig.so
EXPOSE 1883
ENV LD_LIBRARY_PATH=/usr/local/lib