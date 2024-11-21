# config.py
import os

# Directorio base para almacenar llaves y certificados
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
USERS_DIR = os.path.join(BASE_DIR, 'users')

# Asegurarse de que el directorio de usuarios existe
if not os.path.exists(USERS_DIR):
    os.makedirs(USERS_DIR)

# Ruta de archivos del CA
CA_CERT_FILE = os.path.join(BASE_DIR, 'ca_cert.pem')
CA_KEY_FILE = os.path.join(BASE_DIR, 'ca_key.pem')

# Archivo de usuarios
USERS_FILE = os.path.join(BASE_DIR, 'users.json')

# Archivo de logs
LOG_FILE = os.path.join(BASE_DIR, 'security.log')
