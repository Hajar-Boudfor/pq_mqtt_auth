# pq_mqtt_auth

Post-quantum broker authentication for MQTT 5.0, implemented in Mosquitto 2.1.2 (C plugins) and a Python client (paho-mqtt), using the MQTT 5.0 Enhanced Authentication mechanism.

Both schemes are based on the work of Samandari and Gritti [1] and use the NIST standards ML-KEM-512 (FIPS 203) and ML-DSA-44 (FIPS 204).

| Folder | Scheme | Broker authenticated by | Port | Mean handshake time |
|---|---|---|---|---|
| [`kem_auth/`](kem_auth) | KEM-based | Decapsulation with its static ML-KEM key | 1883 | 2.01 ms |
| [`sig_auth/`](sig_auth) | Signature-based | ML-DSA-44 signature of the handshake | 1884 | 2.48 ms |

Each folder has its own README with installation and usage instructions.
The two brokers use different ports and can run at the same time.

In both schemes, the broker certificate is an X.509 certificate signed with ML-DSA-44 by a dedicated CA, and only the broker is authenticated.

## Reference

[1] J. Samandari and C. Gritti, "Post-Quantum Authentication in the MQTT Protocol", *Journal of Cybersecurity and Privacy*, vol. 3, no. 3, 2023. doi:10.3390/jcp3030021

## Author

Hajar Boudfor
