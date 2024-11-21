# crypto_utils.py
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()

def generate_ecdsa_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()

def save_private_key(private_key, filename, password):
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_private_key(filename, password):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password.encode() if password else None,
    )
    return private_key

def load_public_key(filename):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key

def sign_message(private_key, message, algorithm='RSA'):
    if algorithm == 'RSA':
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    elif algorithm == 'ECDSA':
        signature = private_key.sign(
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
    return signature

def verify_signature(public_key, message, signature, algorithm='RSA'):
    try:
        if algorithm == 'RSA':
            public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif algorithm == 'ECDSA':
            public_key.verify(
                signature,
                message.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
        return True
    except Exception:
        return False

def encrypt_message(public_key, message):
    # Generate a random symmetric key
    symmetric_key = os.urandom(32)
    iv = os.urandom(16)
    # Encrypt the message with the symmetric key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_message = message.encode('utf-8')
    padding_length = 16 - (len(padded_message) % 16)
    padded_message += bytes([padding_length]) * padding_length
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    # Encrypt the symmetric key with the public key
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_symmetric_key, iv, ciphertext

def decrypt_message(private_key, encrypted_symmetric_key, iv, ciphertext):
    # Decrypt the symmetric key with the private key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decrypt the message with the symmetric key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_message[-1]
    message = padded_message[:-padding_length].decode('utf-8')
    return message
