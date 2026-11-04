#!/usr/bin/env sh
set -eu

cert_dir=${SF_CERT_DIR:-"$(dirname "$0")/certs"}
gateway_dns=${SF_GATEWAY_DNS_NAME:-gateway}
mkdir -p "$cert_dir"
chmod 700 "$cert_dir"
if [ -e "$cert_dir/ca.key" ]; then
  echo "Refusing to overwrite existing CA files in $cert_dir" >&2
  exit 1
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$cert_dir/ca.key"
chmod 600 "$cert_dir/ca.key"
openssl req -x509 -new -key "$cert_dir/ca.key" -sha256 -days 3650 \
  -subj "/CN=SentinelForge Development CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$cert_dir/ca.crt"

issue() {
  name=$1
  usage=$2
  san=$3
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$cert_dir/$name.key"
  chmod 600 "$cert_dir/$name.key"
  openssl req -new -key "$cert_dir/$name.key" -subj "/CN=$name" -out "$cert_dir/$name.csr"
  openssl x509 -req -in "$cert_dir/$name.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
    -CAcreateserial -out "$cert_dir/$name.crt" -days 825 -sha256 \
    -extfile /dev/stdin <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=$usage
subjectAltName=$san
EOF
  rm "$cert_dir/$name.csr"
}

issue nats-server serverAuth "DNS:nats,DNS:localhost,IP:127.0.0.1"
issue gateway-server serverAuth "DNS:$gateway_dns,DNS:localhost,IP:127.0.0.1"
for name in gateway-agent gateway-nats eventstore-nats detection-nats ueba-client correlation-client; do
  issue "$name" clientAuth "DNS:$name"
done

echo "Development certificates created in $cert_dir"
echo "Use only in isolated development environments; replace them with certificates from your managed CA."
