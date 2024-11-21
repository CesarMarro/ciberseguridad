# document_signing.py
from PyPDF2 import PdfReader, PdfWriter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
import os
from cryptography.x509.oid import NameOID


def sign_pdf(input_pdf, output_pdf, private_key, cert_pem):
    reader = PdfReader(input_pdf)
    writer = PdfWriter()

    # Copiar todas las páginas al escritor
    for page in reader.pages:
        writer.add_page(page)

    # Calcular el hash del documento
    hasher = hashes.Hash(hashes.SHA256())
    for page in reader.pages:
        text = page.extract_text()
        if text:
            hasher.update(text.encode('utf-8'))
    digest = hasher.finalize()

    # Determinar el tipo de llave y firmar el hash
    if isinstance(private_key, rsa.RSAPrivateKey):
        # Llave RSA
        signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        algorithm = 'RSA'
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        # Llave ECDSA
        signature = private_key.sign(
            digest,
            ec.ECDSA(hashes.SHA256())
        )
        algorithm = 'ECDSA'
    else:
        raise ValueError("Tipo de llave no soportado.")

    # Añadir la firma, el algoritmo y el certificado como metadatos
    writer.add_metadata({
        '/Signature': signature.hex(),
        '/Algorithm': algorithm,
        '/Certificate': cert_pem.decode('utf-8')
    })

    # Escribir el PDF firmado
    with open(output_pdf, 'wb') as f:
        writer.write(f)

def verify_pdf(pdf_path, ca_cert):
    reader = PdfReader(pdf_path)

    # Extraer la firma, el algoritmo y el certificado del firmante
    signature_hex = reader.metadata.get('/Signature')
    algorithm = reader.metadata.get('/Algorithm')
    cert_pem = reader.metadata.get('/Certificate')
    if not signature_hex or not algorithm or not cert_pem:
        return False, "El documento no está firmado o falta información."
    signature = bytes.fromhex(signature_hex)

    # Cargar el certificado del firmante
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())

    # Verificar el certificado del firmante con el certificado de la CA
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        return False, "El certificado del firmante no es válido."

    # Obtener la clave pública del firmante
    public_key = cert.public_key()

    # Calcular el hash del documento
    hasher = hashes.Hash(hashes.SHA256())
    for page in reader.pages:
        text = page.extract_text()
        if text:
            hasher.update(text.encode('utf-8'))
    digest = hasher.finalize()

    # Verificar la firma según el algoritmo
    try:
        if algorithm == 'RSA' and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif algorithm == 'ECDSA' and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                digest,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            return False, "El algoritmo o el tipo de llave no coinciden."
    except Exception:
        return False, "La firma no es válida."

    # Obtener el nombre del firmante
    signer_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    return True, f"La firma es válida. Firmado por: {signer_name}"
