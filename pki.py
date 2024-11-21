# pki.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
import datetime
import os
from config import CA_CERT_FILE, CA_KEY_FILE, USERS_DIR

def create_ca():
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'Mi CA'),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Válido por 10 años
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).sign(private_key, hashes.SHA256())

    # Guardar llave privada de la CA
    with open(CA_KEY_FILE, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Guardar certificado de la CA
    with open(CA_CERT_FILE, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_ca():
    with open(CA_KEY_FILE, 'rb') as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    with open(CA_CERT_FILE, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_private_key, ca_cert

def issue_certificate(public_key, common_name):
    ca_private_key, ca_cert = load_ca()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Válido por 1 año
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u'localhost')]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())

    return cert
