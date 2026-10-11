FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    build-base cmake git \
    openssl-dev cjson-dev

RUN git clone --depth 1 --branch v2.1.2 \
    https://github.com/eclipse/mosquitto.git /opt/mosquitto-src

RUN git clone --depth 1 --branch 0.15.0 \
    https://github.com/open-quantum-safe/liboqs.git /opt/liboqs \
    && cd /opt/liboqs && mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON .. \
    && make -j$(nproc) && make install

WORKDIR /build
COPY Pulgin_Mosquitto.c primitives.c primitives.h /build/

RUN gcc -I/usr/local/include \
        -I/opt/mosquitto-src/include \
        -I. -fPIC -shared \
        Pulgin_Mosquitto.c primitives.c \
        -o auth_kem.so -loqs -lssl -lcrypto

FROM eclipse-mosquitto:2.1.2-alpine
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
RUN mkdir -p /mosquitto/plugins /mosquitto/keys
COPY --from=builder /build/auth_kem.so /mosquitto/plugins/auth_kem.so
EXPOSE 1883
ENV LD_LIBRARY_PATH=/usr/local/lib
