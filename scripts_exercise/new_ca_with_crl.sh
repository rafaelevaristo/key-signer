#!/bin/bash

# ==== CONFIGURATION ====
USER_NAME="Ze da cripto"
USER_EMAIL="zedacriptografia@gmail.com"
COUNTRY="PT"
STATE="Lisboa"
CITY="Lisboa"
ORG="MyOrg da cripto"
CA_NAME="My S/MIME Root CA da cripto"
DAYS_VALID_CA=3650
DAYS_VALID_CERT=825
OUTPUT_DIR="smime-ca"
USER_ID="zedacriptografiasegundo"  # Used for filenames

CA_DIR="${OUTPUT_DIR}/ca"
OPENSSL_CNF="${CA_DIR}/openssl.cnf"
CRL_FILE="${CA_DIR}/crl.pem"

# ==== 0. Prepare directory structure ====
mkdir -p "${CA_DIR}"/{certs,crl,newcerts,private}
mkdir -p "${OUTPUT_DIR}"/{certs,private,requests}

touch "${CA_DIR}/index.txt"
echo 1000 > "${CA_DIR}/serial"
echo 1000 > "${CA_DIR}/crlnumber"

# ==== 1. Create OpenSSL config file ====
cat > "$OPENSSL_CNF" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${CA_DIR}
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl.pem
private_key       = \$dir/private/ca.key
certificate       = \$dir/ca.crt
default_days      = ${DAYS_VALID_CERT}
default_md        = sha256
policy            = policy_loose
x509_extensions   = usr_cert
copy_extensions   = copy

[ policy_loose ]
commonName             = supplied
emailAddress           = optional
organizationName       = optional
organizationalUnitName = optional
stateOrProvinceName    = optional
countryName            = optional
localityName           = optional

[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C  = $COUNTRY
ST = $STATE
L  = $CITY
O  = $ORG
CN = $CA_NAME
emailAddress = ca@example.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = emailProtection
subjectAltName = email:$USER_EMAIL
crlDistributionPoints = URI:https://raw.githubusercontent.com/rafaelevaristo/certificates-ocsp/refs/heads/main/ca1/crl.pem
EOF

# ==== 2. Generate CA key and certificate ====
if [ ! -f "${CA_DIR}/private/ca.key" ]; then
    echo "🔑 Generating CA private key..."
    openssl genpkey -algorithm RSA -out "${CA_DIR}/private/ca.key" -pkeyopt rsa_keygen_bits:4096

    echo "📜 Generating CA self-signed certificate..."
    openssl req -x509 -new -nodes \
        -key "${CA_DIR}/private/ca.key" \
        -sha256 -days "$DAYS_VALID_CA" \
        -out "${CA_DIR}/ca.crt" \
        -config "$OPENSSL_CNF" -extensions v3_ca
else
    echo "✅ CA already exists, skipping CA generation."
fi

# ==== 3. Generate user private key ====
echo "🔑 Generating user private key..."
openssl genpkey -algorithm RSA -out "${OUTPUT_DIR}/private/${USER_ID}.key" -pkeyopt rsa_keygen_bits:2048

# ==== 4. Create CSR ====
echo "📝 Creating certificate signing request (CSR)..."
openssl req -new \
    -key "${OUTPUT_DIR}/private/${USER_ID}.key" \
    -out "${OUTPUT_DIR}/requests/${USER_ID}.csr" \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$USER_NAME/emailAddress=$USER_EMAIL"

# ==== 5. Sign the certificate ====
echo "🔏 Signing user certificate with CA..."
openssl ca -batch \
    -config "$OPENSSL_CNF" \
    -in "${OUTPUT_DIR}/requests/${USER_ID}.csr" \
    -out "${OUTPUT_DIR}/certs/${USER_ID}.crt"

# ==== 6. Create PKCS#12 ====
echo "📦 Creating PKCS#12 (.p12) bundle..."
openssl pkcs12 -export \
    -inkey "${OUTPUT_DIR}/private/${USER_ID}.key" \
    -in "${OUTPUT_DIR}/certs/${USER_ID}.crt" \
    -certfile "${CA_DIR}/ca.crt" \
    -out "${OUTPUT_DIR}/${USER_ID}_smime.p12"

# ==== 7. Generate initial CRL ====
echo "🧾 Generating CRL..."
openssl ca -config "$OPENSSL_CNF" -gencrl -out "$CRL_FILE"

# ==== 8. Done ====
echo -e "\n✅ All done!"
echo "➡️ Output files:"
echo "  - ${CA_DIR}/ca.crt ........... CA certificate (must be trusted manually)"
echo "  - ${OUTPUT_DIR}/certs/${USER_ID}.crt ..... User's certificate"
echo "  - ${OUTPUT_DIR}/private/${USER_ID}.key ... User's private key"
echo "  - ${OUTPUT_DIR}/${USER_ID}_smime.p12 ..... Import this into your email client"
echo "  - ${CRL_FILE} ................. Certificate Revocation List (CRL)"

echo -e "\n🔁 To revoke the certificate and regenerate the CRL:"
echo "   openssl ca -config \"$OPENSSL_CNF\" -revoke \"${OUTPUT_DIR}/certs/${USER_ID}.crt\""
echo "   openssl ca -config \"$OPENSSL_CNF\" -gencrl -out \"$CRL_FILE\""

















