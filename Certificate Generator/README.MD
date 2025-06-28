# User Security with TLS 1.3

This repository provides tools to generate both a **self-signed certificate** and a **certificate signing request (CSR)** for use with a Certificate Authority (CA). These certificates allow integration of **TLS 1.3** into your applications with a strong focus on secure user authentication.

## 🔐 Features

- Generate a **self-signed certificate** for development environments.
- Generate a **CSR** for production deployment via a trusted CA.
- Use **TLS 1.3** to secure communication between clients and your server.
- Written in **C++** using OpenSSL with minimal external dependencies.

## 🧪 Development Use (Self-Signed Certificate)

Use the self-signed certificate to:

- Enable TLS 1.3 on local development servers
- Securely test encrypted connections
- Avoid exposing credentials in plaintext over unencrypted HTTP

> ⚠️ Self-signed certificates are not trusted by clients by default. Only use them for testing and development.

## 🚀 Production Use (CSR to CA)

The CSR can be submitted to a trusted Certificate Authority (e.g., Let's Encrypt, DigiCert) and:

- Must be associated with a valid domain name (not `localhost`)
- Enables trusted TLS connections in browsers and mobile apps
- Moves the server from a local testbed to secure production infrastructure


## 🔧 Requirements

- OpenSSL (>= 1.1.1 for TLS 1.3 support)
- C++17 compiler (e.g., `g++ -std=c++17`)
- Linux environment (e.g., Ubuntu 22.04 on WSL or native)

## ⚙️ Usage

Compile with:
```bash
g++ generate_self_signed.cpp -o generate_cert -lssl -lcrypto -std=c++17
g++ generate_csr.cpp -o generate_csr -lssl -lcrypto -std=c++17


