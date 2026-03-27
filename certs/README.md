# Kafka mTLS Certificates

Place your Kafka mTLS certificates here:

```
certs/
  ca.crt        - Kafka CA certificate (or truststore CA)
  client.crt    - Client certificate (with TLS Web Client Authentication)
  client.key    - Client private key
```

These files are mounted read-only into the ai-service container at `/app/certs/`.

**Do not commit certificates to git.** The `certs/` directory is gitignored
(except this README).

## Getting the certificates

You need:
1. **CA certificate** - the CA that signed the Kafka broker certificates
2. **Client certificate + key** - signed by a CA the Kafka brokers trust,
   with the "TLS Web Client Authentication" extension

## Converting from JKS (Java KeyStore)

If you received Java keystores (`.jks` files), convert to PEM format:

### Extract CA cert from truststore
```bash
keytool -exportcert -alias <alias> -keystore consumer.truststore.jks \
  -rfc -file ca.crt
# Enter truststore password when prompted

# If you don't know the alias:
keytool -list -keystore consumer.truststore.jks
```

### Extract client cert + key from keystore
```bash
# Convert JKS to PKCS12 first
keytool -importkeystore \
  -srckeystore consumer.keystore.jks \
  -destkeystore temp.p12 \
  -deststoretype PKCS12 \
  -srcstorepass <keystore_password> \
  -deststorepass <temp_password>

# Extract client certificate
openssl pkcs12 -in temp.p12 -clcerts -nokeys -out client.crt \
  -passin pass:<temp_password>

# Extract private key
openssl pkcs12 -in temp.p12 -nocerts -nodes -out client.key \
  -passin pass:<temp_password>

# Clean up
rm temp.p12
chmod 600 client.key
```

### If you have separate .crt and .key files already
```bash
# Just copy them directly
cp /path/to/project.crt certs/client.crt
cp /path/to/project.key certs/client.key
cp /path/to/broker-ca.crt certs/ca.crt
chmod 644 certs/ca.crt certs/client.crt
chmod 600 certs/client.key
```

## Configuration

Set these in your `.env` file:

```bash
# Kafka broker address (bootstrap server)
KAFKA_BROKERS=kafka-broker.example.com:9093

# If private key is password-protected:
KAFKA_SSL_KEY_PASSWORD=your_key_password

# If connecting via HA proxy (cert CN doesn't match proxy hostname):
KAFKA_SSL_ENDPOINT_ALGO=none
```

## Testing the connection

From the Docker host:
```bash
# Test TLS handshake
openssl s_client -connect <kafka-broker>:9093 \
  -cert certs/client.crt \
  -key certs/client.key \
  -CAfile certs/ca.crt

# Test from inside Docker
docker exec ai-log-service python3 -c "
from confluent_kafka import Consumer
c = Consumer({
    'bootstrap.servers': '<broker>:9093',
    'group.id': 'test',
    'security.protocol': 'SSL',
    'ssl.ca.location': '/app/certs/ca.crt',
    'ssl.certificate.location': '/app/certs/client.crt',
    'ssl.key.location': '/app/certs/client.key',
    'ssl.endpoint.identification.algorithm': 'none',
})
print(c.list_topics(timeout=10))
c.close()
"
```

## Troubleshooting

**"SSL handshake failed"** - Check that the CA cert matches the broker's CA.
Try with `ssl.endpoint.identification.algorithm=none` if using HA proxy.

**"Certificate verify failed"** - The CA cert doesn't match. You may need
the intermediate CA chain, not just the root CA.

**"No such file"** - Certificates not mounted. Check `docker compose` volume
mount and file permissions.

**"Key password required"** - Set `KAFKA_SSL_KEY_PASSWORD` in `.env`.
