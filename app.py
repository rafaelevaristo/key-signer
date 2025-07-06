from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import json
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import tempfile
import zipfile
from io import BytesIO

app = Flask(__name__)
CORS(app)

# Storage directories
DATA_DIR = "data"
KEYS_DIR = os.path.join(DATA_DIR, "keys")
CAS_DIR = os.path.join(DATA_DIR, "cas")
CERTS_DIR = os.path.join(DATA_DIR, "certificates")
CSRS_DIR = os.path.join(DATA_DIR, "csrs")

# Create directories if they don't exist
for dir_path in [DATA_DIR, KEYS_DIR, CAS_DIR, CERTS_DIR, CSRS_DIR]:
    os.makedirs(dir_path, exist_ok=True)

# Data files
CAS_DB = os.path.join(DATA_DIR, "cas.json")
KEYS_DB = os.path.join(DATA_DIR, "keys.json")
CSRS_DB = os.path.join(DATA_DIR, "csrs.json")
CERTS_DB = os.path.join(DATA_DIR, "certificates.json")

def load_json_db(file_path):
    """Load JSON database file"""
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    return {}

def save_json_db(file_path, data):
    """Save JSON database file"""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)

def get_key_usage_extension(purpose):
    """Get key usage extension based on purpose"""
    if purpose == "server_auth":
        return x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )
    elif purpose == "client_auth":
        return x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )
    elif purpose == "smime":
        return x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=True,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )
    else:  # CA
        return x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    """Generate a new RSA key pair"""
    try:
        data = request.get_json()
        purpose = data.get('purpose', 'server_auth')
        key_size = int(data.get('key_size', 2048))
        name = data.get('name', f"{purpose} Key") # New: Get name from request, default to purpose
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        
        # Generate key ID
        key_id = str(uuid.uuid4())
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Save keys to files
        private_key_file = os.path.join(KEYS_DIR, f"{key_id}_private.pem")
        public_key_file = os.path.join(KEYS_DIR, f"{key_id}_public.pem")
        
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        
        # Save to database
        keys_db = load_json_db(KEYS_DB)
        keys_db[key_id] = {
            'id': key_id,
            'name': name, # New: Store the name
            'purpose': purpose,
            'key_size': key_size,
            'created_at': datetime.now().isoformat(),
            'private_key_file': private_key_file,
            'public_key_file': public_key_file
        }
        save_json_db(KEYS_DB, keys_db)
        
        return jsonify({
            'success': True,
            'key_id': key_id,
            'name': name, # New: Return the name
            'purpose': purpose,
            'key_size': key_size,
            'created_at': keys_db[key_id]['created_at']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/keys', methods=['GET'])
def list_keys():
    """List all generated keys"""
    keys_db = load_json_db(KEYS_DB)
    return jsonify(list(keys_db.values()))

@app.route('/api/create-csr', methods=['POST'])
def create_csr():
    """Create a Certificate Signing Request"""
    try:
        data = request.get_json()
        key_id = data.get('key_id')
        subject_data = data.get('subject', {})
        
        # Load private key
        keys_db = load_json_db(KEYS_DB)
        if key_id not in keys_db:
            return jsonify({'success': False, 'error': 'Key not found'}), 404
        
        key_info = keys_db[key_id]
        with open(key_info['private_key_file'], 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        # Build subject
        subject_components = []
        if subject_data.get('country'):
            subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject_data['country']))
        if subject_data.get('state'):
            subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_data['state']))
        if subject_data.get('city'):
            subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject_data['city']))
        if subject_data.get('organization'):
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data['organization']))
        if subject_data.get('organizational_unit'):
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_data['organizational_unit']))
        if subject_data.get('common_name'):
            subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_data['common_name']))
        if subject_data.get('email'):
            subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_data['email']))
        
        subject = x509.Name(subject_components)
        
        # Create CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject)
        
        # Add key usage extension
        key_usage = get_key_usage_extension(key_info['purpose'])
        csr = csr.add_extension(key_usage, critical=True)

        # Add Subject Alternative Name for S/MIME
        if key_info['purpose'] == "smime" and subject_data.get('email'):
            csr = csr.add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(subject_data['email'])]),
                critical=False,
            )
        
        # Sign CSR
        csr = csr.sign(private_key, hashes.SHA256())
        
        # Generate CSR ID
        csr_id = str(uuid.uuid4())
        
        # Save CSR
        csr_file = os.path.join(CSRS_DIR, f"{csr_id}.csr")
        with open(csr_file, 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        
        # Save to database
        csrs_db = load_json_db(CSRS_DB)
        csrs_db[csr_id] = {
            'id': csr_id,
            'key_id': key_id,
            'subject': subject_data,
            'purpose': key_info['purpose'],
            'created_at': datetime.now().isoformat(),
            'csr_file': csr_file,
            'signed': False
        }
        save_json_db(CSRS_DB, csrs_db)
        
        return jsonify({
            'success': True,
            'csr_id': csr_id,
            'subject': subject_data,
            'purpose': key_info['purpose']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/csrs', methods=['GET'])
def list_csrs():
    """List all CSRs"""
    csrs_db = load_json_db(CSRS_DB)
    return jsonify(list(csrs_db.values()))

@app.route('/api/create-ca', methods=['POST'])
def create_ca():
    """Create a new Certificate Authority"""
    try:
        data = request.get_json()
        subject_data = data.get('subject', {})
        validity_days = int(data.get('validity_days', 365))
        key_size = int(data.get('key_size', 2048))
        
        # Generate CA private key
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        
        # Build subject
        subject_components = []
        if subject_data.get('country'):
            subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject_data['country']))
        if subject_data.get('state'):
            subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_data['state']))
        if subject_data.get('city'):
            subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject_data['city']))
        if subject_data.get('organization'):
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data['organization']))
        if subject_data.get('organizational_unit'):
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_data['organizational_unit']))
        if subject_data.get('common_name'):
            subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_data['common_name']))
        if subject_data.get('email'):
            subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_data['email']))
        
        subject = x509.Name(subject_components)
        
        # Create CA certificate
        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject  # Self-signed
        ).public_key(
            ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            get_key_usage_extension('ca'),
            critical=True,
        )
        
        if subject_data.get('email'):
            ca_cert = ca_cert.add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(subject_data['email'])]),
                critical=False,
            )
        else:
            ca_cert = ca_cert.add_extension(
                x509.SubjectAlternativeName([]),
                critical=False,
            )
        
        ca_cert = ca_cert.sign(ca_private_key, hashes.SHA256())
        
        # Generate CA ID
        ca_id = str(uuid.uuid4())
        
        # Save CA files
        ca_cert_file = os.path.join(CAS_DIR, f"{ca_id}_cert.pem")
        ca_key_file = os.path.join(CAS_DIR, f"{ca_id}_key.pem")
        
        with open(ca_cert_file, 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(ca_key_file, 'wb') as f:
            f.write(ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save to database
        cas_db = load_json_db(CAS_DB)
        cas_db[ca_id] = {
            'id': ca_id,
            'subject': subject_data,
            'serial_number': str(ca_cert.serial_number),
            'not_valid_before': ca_cert.not_valid_before.isoformat(),
            'not_valid_after': ca_cert.not_valid_after.isoformat(),
            'key_size': key_size,
            'created_at': datetime.now().isoformat(),
            'cert_file': ca_cert_file,
            'key_file': ca_key_file,
            'type': 'created'
        }
        save_json_db(CAS_DB, cas_db)
        
        return jsonify({
            'success': True,
            'ca_id': ca_id,
            'subject': subject_data,
            'serial_number': cas_db[ca_id]['serial_number'],
            'not_valid_after': cas_db[ca_id]['not_valid_after']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/cas', methods=['GET'])
def list_cas():
    """List all Certificate Authorities"""
    cas_db = load_json_db(CAS_DB)
    return jsonify(list(cas_db.values()))

@app.route('/api/sign-csr', methods=['POST'])
def sign_csr():
    """Sign a CSR with a CA"""
    try:
        data = request.get_json()
        csr_id = data.get('csr_id')
        ca_id = data.get('ca_id')
        validity_days = int(data.get('validity_days', 365))
        
        # Load CSR
        csrs_db = load_json_db(CSRS_DB)
        if csr_id not in csrs_db:
            return jsonify({'success': False, 'error': 'CSR not found'}), 404
        
        csr_info = csrs_db[csr_id]
        with open(csr_info['csr_file'], 'rb') as f:
            csr = x509.load_pem_x509_csr(f.read())
        
        # Load CA
        cas_db = load_json_db(CAS_DB)
        if ca_id not in cas_db:
            return jsonify({'success': False, 'error': 'CA not found'}), 404
        
        ca_info = cas_db[ca_id]
        with open(ca_info['cert_file'], 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(ca_info['key_file'], 'rb') as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        )
        
        # Copy extensions from CSR
        for extension in csr.extensions:
            cert = cert.add_extension(extension.value, critical=extension.critical)
        
        # Sign certificate
        cert = cert.sign(ca_private_key, hashes.SHA256())
        
        # Generate certificate ID
        cert_id = str(uuid.uuid4())
        
        # Save certificate
        cert_file = os.path.join(CERTS_DIR, f"{cert_id}.pem")
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Save to database
        certs_db = load_json_db(CERTS_DB)
        certs_db[cert_id] = {
            'id': cert_id,
            'csr_id': csr_id,
            'ca_id': ca_id,
            'subject': csr_info['subject'],
            'serial_number': str(cert.serial_number),
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
            'purpose': csr_info['purpose'],
            'created_at': datetime.now().isoformat(),
            'cert_file': cert_file
        }
        save_json_db(CERTS_DB, certs_db)
        
        # Mark CSR as signed
        csrs_db[csr_id]['signed'] = True
        csrs_db[csr_id]['cert_id'] = cert_id
        save_json_db(CSRS_DB, csrs_db)
        
        return jsonify({
            'success': True,
            'cert_id': cert_id,
            'serial_number': certs_db[cert_id]['serial_number'],
            'not_valid_after': certs_db[cert_id]['not_valid_after']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/certificates', methods=['GET'])
def list_certificates():
    """List all certificates"""
    certs_db = load_json_db(CERTS_DB)
    return jsonify(list(certs_db.values()))

@app.route('/api/download/key/<key_id>/<key_type>')
def download_key(key_id, key_type):
    """Download public or private key"""
    try:
        keys_db = load_json_db(KEYS_DB)
        if key_id not in keys_db:
            return jsonify({'error': 'Key not found'}), 404
        
        key_info = keys_db[key_id]
        
        if key_type == 'public':
            return send_file(key_info['public_key_file'], as_attachment=True,
                           download_name=f"{key_id}_public.pem")
        elif key_type == 'private':
            return send_file(key_info['private_key_file'], as_attachment=True,
                           download_name=f"{key_id}_private.pem")
        else:
            return jsonify({'error': 'Invalid key type'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/ca/<ca_id>/<file_type>')
def download_ca(ca_id, file_type):
    """Download CA certificate or private key"""
    try:
        cas_db = load_json_db(CAS_DB)
        if ca_id not in cas_db:
            return jsonify({'error': 'CA not found'}), 404
        
        ca_info = cas_db[ca_id]
        
        if file_type == 'cert':
            return send_file(ca_info['cert_file'], as_attachment=True,
                           download_name=f"ca_{ca_id}.pem")
        elif file_type == 'key':
            return send_file(ca_info['key_file'], as_attachment=True,
                           download_name=f"ca_{ca_id}_key.pem")
        else:
            return jsonify({'error': 'Invalid file type'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/certificate/<cert_id>')
def download_certificate(cert_id):
    """Download certificate"""
    try:
        certs_db = load_json_db(CERTS_DB)
        if cert_id not in certs_db:
            return jsonify({'error': 'Certificate not found'}), 404
        
        cert_info = certs_db[cert_id]
        return send_file(cert_info['cert_file'], as_attachment=True,
                       download_name=f"cert_{cert_id}.pem")
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/csr/<csr_id>')
def download_csr(csr_id):
    """Download CSR"""
    try:
        csrs_db = load_json_db(CSRS_DB)
        if csr_id not in csrs_db:
            return jsonify({'error': 'CSR not found'}), 404
        
        csr_info = csrs_db[csr_id]
        return send_file(csr_info['csr_file'], as_attachment=True,
                       download_name=f"csr_{csr_id}.csr")
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def serve_index():
    return send_file('index.html')

@app.route('/api/download/pfx/<cert_id>', methods=['GET'])
def download_pfx(cert_id):
    """Download certificate and private key as PFX/P12"""
    try:
        certs_db = load_json_db(CERTS_DB)
        if cert_id not in certs_db:
            return jsonify({'error': 'Certificate not found'}), 404
        
        cert_info = certs_db[cert_id]
        
        # Load certificate
        with open(cert_info['cert_file'], 'rb') as f:
            certificate = x509.load_pem_x509_certificate(f.read())
        
        # Find associated private key
        csrs_db = load_json_db(CSRS_DB)
        csr_id = cert_info['csr_id']
        if csr_id not in csrs_db:
            return jsonify({'error': 'Associated CSR not found'}), 404
        
        csr_info = csrs_db[csr_id]
        key_id = csr_info['key_id']
        
        keys_db = load_json_db(KEYS_DB)
        if key_id not in keys_db:
            return jsonify({'error': 'Associated key not found'}), 404
        
        key_info = keys_db[key_id]
        with open(key_info['private_key_file'], 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        # Get password from query parameter (optional)
        password = request.args.get('password')
        if password:
            encryption_algorithm = BestAvailableEncryption(password.encode('utf-8'))
        else:
            encryption_algorithm = serialization.NoEncryption()

        # Serialize to PFX
        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=certificate.subject.rfc4514_string().encode('utf-8'),
            key=private_key,
            cert=certificate,
            cas=None, # No CA chain for now
            encryption_algorithm=encryption_algorithm
        )
        
        return send_file(BytesIO(pfx_bytes), as_attachment=True,
                       download_name=f"cert_{cert_id}.pfx",
                       mimetype='application/x-pkcs12')
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/onestop-cert', methods=['POST'])
def onestop_cert():
    """Generate key, create CSR, and sign certificate in one go"""
    try:
        data = request.get_json()
        
        # Key Generation Parameters
        key_purpose = data.get('key_purpose', 'server_auth')
        key_size = int(data.get('key_size', 2048))
        key_name = data.get('key_name', f"{key_purpose} Key")

        # Subject Data for CSR
        subject_data = data.get('subject', {})

        # CA and Validity for Signing
        ca_id = data.get('ca_id')
        validity_days = int(data.get('validity_days', 365))

        # 1. Generate Key Pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        key_id = str(uuid.uuid4())
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_file = os.path.join(KEYS_DIR, f"{key_id}_private.pem")
        public_key_file = os.path.join(KEYS_DIR, f"{key_id}_public.pem")
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        keys_db = load_json_db(KEYS_DB)
        keys_db[key_id] = {
            'id': key_id,
            'name': key_name,
            'purpose': key_purpose,
            'key_size': key_size,
            'created_at': datetime.now().isoformat(),
            'private_key_file': private_key_file,
            'public_key_file': public_key_file
        }
        save_json_db(KEYS_DB, keys_db)

        # 2. Create CSR
        subject_components = []
        if subject_data.get('country'):
            subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject_data['country']))
        if subject_data.get('state'):
            subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_data['state']))
        if subject_data.get('city'):
            subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject_data['city']))
        if subject_data.get('organization'):
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data['organization']))
        if subject_data.get('organizational_unit'):
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_data['organizational_unit']))
        if subject_data.get('common_name'):
            subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_data['common_name']))
        if subject_data.get('email'):
            subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_data['email']))
        
        subject = x509.Name(subject_components)
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        key_usage = get_key_usage_extension(key_purpose)
        csr_builder = csr_builder.add_extension(key_usage, critical=True)
        if key_purpose == "smime" and subject_data.get('email'):
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(subject_data['email'])]), 
                critical=False,
            )
        csr = csr_builder.sign(private_key, hashes.SHA256())
        csr_id = str(uuid.uuid4())
        csr_file = os.path.join(CSRS_DIR, f"{csr_id}.csr")
        with open(csr_file, 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        csrs_db = load_json_db(CSRS_DB)
        csrs_db[csr_id] = {
            'id': csr_id,
            'key_id': key_id,
            'subject': subject_data,
            'purpose': key_purpose,
            'created_at': datetime.now().isoformat(),
            'csr_file': csr_file,
            'signed': False
        }
        save_json_db(CSRS_DB, csrs_db)

        # 3. Sign Certificate
        cas_db = load_json_db(CAS_DB)
        if ca_id not in cas_db:
            return jsonify({'success': False, 'error': 'CA not found'}), 404
        ca_info = cas_db[ca_id]
        with open(ca_info['cert_file'], 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_info['key_file'], 'rb') as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        )
        for extension in csr.extensions:
            cert = cert.add_extension(extension.value, critical=extension.critical)
        cert = cert.sign(ca_private_key, hashes.SHA256())
        cert_id = str(uuid.uuid4())
        cert_file = os.path.join(CERTS_DIR, f"{cert_id}.pem")
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        certs_db = load_json_db(CERTS_DB)
        certs_db[cert_id] = {
            'id': cert_id,
            'csr_id': csr_id,
            'ca_id': ca_id,
            'subject': subject_data,
            'serial_number': str(cert.serial_number),
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
            'purpose': key_purpose,
            'created_at': datetime.now().isoformat(),
            'cert_file': cert_file
        }
        save_json_db(CERTS_DB, certs_db)
        csrs_db[csr_id]['signed'] = True
        csrs_db[csr_id]['cert_id'] = cert_id
        save_json_db(CSRS_DB, csrs_db)

        return jsonify({
            'success': True,
            'cert_id': cert_id,
            'key_id': key_id,
            'csr_id': csr_id,
            'serial_number': certs_db[cert_id]['serial_number'],
            'not_valid_after': certs_db[cert_id]['not_valid_after']
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)