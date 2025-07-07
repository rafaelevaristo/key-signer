#!/bin/bash

# ==== CONFIGURATION ====
USER_NAME="Rafael Evaristo"
USER_EMAIL="rafael@example.com"
COUNTRY="PT"
STATE="Lisboa"
CITY="Lisboa"
ORG="MyOrg"
CA_NAME="My S/MIME Root CA"
DAYS_VALID_CA=3650
DAYS_VALID_CERT=825
OUTPUT_DIR="smime-ca"
USER_ID="user"  # Used for filenames

# ==== STRUCTURE ====
mkdir -p "$OUTPUT_DIR"/{ca/certs,ca/private,certs,private,requests,newcerts}
touch "$OUTPUT_DIR/index.txt"
echo 1000 > "$OUTPUT_DIR/serial"

cd "$OUTPUT_DIR" || exit

# ==== 1. Generate CA key and cert ====
if [ ! -f ca/private/ca.key ]; then
    echo "🔑 Generating CA private key..."
    openssl genpkey -algorithm RSA -out ca/private/ca.key -pkeyopt rsa_keygen_bits:4096
    echo "📜 Generating CA self-signed certificate..."
    openssl req -x509 -new -nodes -key ca/private/ca.key -sha256 -days "$DAYS_VALID_CA" \
        -out ca/ca.crt \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CA_NAME/emailAddress=ca@example.com"
else
    echo "✅ CA already exists, skipping CA generation."
fi

# ==== 2. Generate user private key ====
echo "🔑 Generating user private key..."
openssl genpkey -algorithm RSA -out private/${USER_ID}.key -pkeyopt rsa_keygen_bits:2048

# ==== 3. Create CSR ====
echo "📝 Creating certificate signing request (CSR)..."
openssl req -new -key private/${USER_ID}.key -out requests/${USER_ID}.csr \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$USER_NAME/emailAddress=$USER_EMAIL"

# ==== 4. Create S/MIME extensions config ====
cat > smime_ext.cnf <<EOF
[smime_ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = emailProtection
subjectAltName = email:$USER_EMAIL
EOF

# ==== 5. Sign the user CSR with the CA ====
echo "🔏 Signing user certificate with CA..."
openssl x509 -req \
    -in requests/${USER_ID}.csr \
    -CA ca/ca.crt \
    -CAkey ca/private/ca.key \
    -CAcreateserial \
    -out certs/${USER_ID}.crt \
    -days "$DAYS_VALID_CERT" \
    -sha256 \
    -extfile smime_ext.cnf \
    -extensions smime_ext

# ==== 6. Create .p12 bundle for email client ====
echo "📦 Creating PKCS#12 (.p12) bundle..."
openssl pkcs12 -export \
    -inkey private/${USER_ID}.key \
    -in certs/${USER_ID}.crt \
    -certfile ca/ca.crt \
    -out ${USER_ID}_smime.p12

echo -e "\n✅ All done!"
echo "➡️ Output files:"
echo "  - ${OUTPUT_DIR}/ca/ca.crt ........... CA certificate (must be trusted manually)"
echo "  - ${OUTPUT_DIR}/certs/${USER_ID}.crt ....... User's certificate"
echo "  - ${OUTPUT_DIR}/private/${USER_ID}.key ..... User's private key"
echo "  - ${OUTPUT_DIR}/${USER_ID}_smime.p12 ........ Import this into your email client"
