# Kafka mTLS Certificates

Place your Kafka mTLS certificates here:

```
certs/
  ca.crt        - Kafka CA certificate (or CA chain)
  client.crt    - Client certificate
  client.key    - Client private key
```

These files are mounted read-only into the ai-service container at `/app/certs/`.

**Do not commit certificates to git.** The `certs/` directory is gitignored
(except this README).

## Getting the certificates

Ask your Kafka team for:
1. The CA certificate that signed the Kafka broker certificates
2. A client certificate + key pair signed by a CA that the Kafka brokers trust

## Testing the connection

From the Docker host:
```bash
openssl s_client -connect <kafka-broker>:9093 \
  -cert certs/client.crt \
  -key certs/client.key \
  -CAfile certs/ca.crt
```

## File permissions

Ensure the key file is readable:
```bash
chmod 644 certs/ca.crt certs/client.crt
chmod 600 certs/client.key
```
