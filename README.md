# Certificate Management System

This project provides a web-based interface for managing cryptographic keys, Certificate Signing Requests (CSRs), Certificate Authorities (CAs), and certificates. It allows for key generation, CSR creation, CA management, and certificate signing, including a simplified "one-stop" process for generating and signing certificates.

## Table of Contents
- [User Manual and Cryptography Guide](USER_MANUAL.md)
- [Features](#features)
- [Running Locally (PC)](#running-locally-pc)
- [Running with Docker](#running-with-docker)
- [Accessing the Application](#accessing-the-application)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)

## Features
- Generate RSA key pairs (2048, 3072, 4096 bits) with assignable names.
- Create Certificate Signing Requests (CSRs) from generated keys, including S/MIME email support.
- Create self-signed Certificate Authorities (CAs).
- Sign CSRs using existing CAs.
- Download public/private keys, CA certificates/keys, and issued certificates.
- Export certificates with their private keys in PFX/P12 format (with optional password protection).
- "One-Stop" certificate generation: generate a key, create a CSR, and sign it with a selected CA in a single step.

## Running Locally (PC)

### Prerequisites
- Python 3.10 or higher
- pip (Python package installer)

### Installation
1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <repository_url>
    cd key-signer
    ```
    (Note: Replace `<repository_url>` with the actual URL of your repository.)

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    If you encounter issues with `Werkzeug` or `Flask` versions, you might need to downgrade them:
    ```bash
    pip uninstall Werkzeug Flask -y
    pip install Werkzeug==2.0.3 Flask==2.0.3
    ```

### Running the Application
To start the Flask development server:
```bash
python3 app.py
```

## Running with Docker

### Prerequisites
- Docker installed and running on your system.

### Building the Docker Image
Navigate to the root directory of the project (where `Dockerfile` is located) and run:
```bash
docker build -t key-signer .
```
This command builds a Docker image named `key-signer`.

### Running the Docker Container
Once the image is built, you can run a container from it:
```bash
docker run -p 5000:5000 key-signer
```
This command runs the `key-signer` container and maps port 5000 on your host machine to port 5000 inside the container.

## Accessing the Application
Once the application is running (either locally or via Docker), open your web browser and navigate to:
```
http://localhost:5000
```

## API Endpoints
The application exposes a RESTful API. All API endpoints are prefixed with `/api`.
- `/api/generate-key` (POST): Generate a new RSA key pair.
- `/api/keys` (GET): List all generated keys.
- `/api/create-csr` (POST): Create a Certificate Signing Request.
- `/api/csrs` (GET): List all CSRs.
- `/api/create-ca` (POST): Create a new Certificate Authority.
- `/api/cas` (GET): List all Certificate Authorities.
- `/api/sign-csr` (POST): Sign a CSR with a CA.
- `/api/certificates` (GET): List all issued certificates.
- `/api/download/key/<key_id>/<key_type>` (GET): Download public or private key.
- `/api/download/ca/<ca_id>/<file_type>` (GET): Download CA certificate or private key.
- `/api/download/certificate/<cert_id>` (GET): Download certificate.
- `/api/download/csr/<csr_id>` (GET): Download CSR.
- `/api/download/pfx/<cert_id>` (GET): Download certificate and private key as PFX/P12.
- `/api/onestop-cert` (POST): Generate key, create CSR, and sign certificate in one go.

## Project Structure
```
.
├── app.py                # Flask application backend
├── index.html            # Frontend HTML, CSS, and JavaScript
├── requirements.txt      # Python dependencies
├── Dockerfile            # Docker build instructions
└── .gitignore            # Git ignore file
└── README.md             # This README file
└── data/                 # Directory for storing generated keys, CAs, CSRs, and certificates (ignored by Git)
    ├── cas/
    ├── certificates/
    ├── csrs/
    └── keys/
```
