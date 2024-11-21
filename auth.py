# auth.py
import bcrypt
import json
import os
from config import USERS_FILE

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def register_user(username, password, role='user'):
    users = load_users()
    if username in users:
        return False, "El usuario ya existe."
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = {'password': hashed.decode('utf-8'), 'role': role}
    save_users(users)
    return True, "Usuario registrado exitosamente."

def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        return False, "Usuario no encontrado."
    hashed = users[username]['password'].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), hashed):
        return True, users[username]['role']
    else:
        return False, "Contraseña incorrecta."
