# gui.py
import sys
from PyQt5 import QtWidgets, QtGui, QtCore
from auth import register_user, authenticate_user
from crypto_utils import *
from document_signing import *
from pki import create_ca, issue_certificate
import logging
import os
from config import USERS_DIR, CA_CERT_FILE
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

class LoginWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Inicio de Sesión')
        self.setGeometry(100, 100, 400, 200)
        self.init_ui()

    def init_ui(self):
        layout = QtWidgets.QVBoxLayout()

        self.username = QtWidgets.QLineEdit()
        self.username.setPlaceholderText('Nombre de Usuario')
        self.password = QtWidgets.QLineEdit()
        self.password.setPlaceholderText('Contraseña')
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login_button = QtWidgets.QPushButton('Iniciar Sesión')
        self.register_button = QtWidgets.QPushButton('Registrarse')

        layout.addWidget(self.username)
        layout.addWidget(self.password)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

        self.login_button.clicked.connect(self.login)
        self.register_button.clicked.connect(self.register)

    def login(self):
        username = self.username.text()
        password = self.password.text()
        success, result = authenticate_user(username, password)
        if success:
            logging.info(f"Usuario '{username}' inició sesión.")
            self.main_window = MainWindow(username)
            self.main_window.show()
            self.close()
        else:
            QtWidgets.QMessageBox.warning(self, 'Error', result)
            logging.warning(f"Intento de inicio de sesión fallido para '{username}'.")

    def register(self):
        username = self.username.text()
        password = self.password.text()
        success, result = register_user(username, password)
        if success:
            # Solicitar al usuario que elija un algoritmo
            algorithm, ok_alg = QtWidgets.QInputDialog.getItem(
                self,
                'Algoritmo',
                'Seleccione el algoritmo para generar sus llaves:',
                ['RSA', 'ECDSA'],
                0,
                False
            )
            if ok_alg:
                # Generar las llaves basadas en el algoritmo seleccionado
                if algorithm == 'RSA':
                    private_key, public_key = generate_rsa_keys()
                else:
                    private_key, public_key = generate_ecdsa_keys()
                # Solicitar una contraseña para proteger la llave privada
                key_password, ok_pass = QtWidgets.QInputDialog.getText(
                    self,
                    'Contraseña de Llave Privada',
                    'Ingrese una contraseña para proteger su llave privada:',
                    QtWidgets.QLineEdit.Password
                )
                if ok_pass:
                    # Crear directorio del usuario
                    user_dir = os.path.join(USERS_DIR, username)
                    if not os.path.exists(user_dir):
                        os.makedirs(user_dir)
                    # Guardar las llaves
                    private_key_path = os.path.join(user_dir, 'private_key.pem')
                    public_key_path = os.path.join(user_dir, 'public_key.pem')
                    cert_path = os.path.join(user_dir, 'cert.pem')
                    save_private_key(private_key, private_key_path, key_password)
                    save_public_key(public_key, public_key_path)
                    # Emitir un certificado
                    cert = issue_certificate(public_key, username)
                    # Guardar el certificado
                    with open(cert_path, 'wb') as f:
                        f.write(cert.public_bytes(serialization.Encoding.PEM))
                    QtWidgets.QMessageBox.information(self, 'Éxito', 'Usuario registrado y llaves generadas correctamente.')
                    logging.info(f"Usuario '{username}' registrado y llaves generadas.")
                else:
                    QtWidgets.QMessageBox.warning(self, 'Error', 'La generación de llaves fue cancelada.')
                    logging.warning(f"Usuario '{username}' canceló la generación de llaves.")
            else:
                QtWidgets.QMessageBox.warning(self, 'Error', 'La selección de algoritmo fue cancelada.')
                logging.warning(f"Usuario '{username}' canceló la selección de algoritmo.")
        else:
            QtWidgets.QMessageBox.warning(self, 'Error', result)
            logging.warning(f"Intento de registro fallido para '{username}'.")

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle('Aplicación de Firmas Digitales')
        self.setGeometry(100, 100, 800, 600)
        self.init_ui()

    def init_ui(self):
        # Menú
        menubar = self.menuBar()
        file_menu = menubar.addMenu('Archivo')
        sign_menu = menubar.addMenu('Firmar')
        verify_menu = menubar.addMenu('Verificar')
        encrypt_menu = menubar.addMenu('Encriptar')
        decrypt_menu = menubar.addMenu('Desencriptar')

        # Acciones
        exit_action = QtWidgets.QAction('Salir', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        sign_message_action = QtWidgets.QAction('Firmar Mensaje', self)
        sign_message_action.triggered.connect(self.sign_message)
        sign_menu.addAction(sign_message_action)

        sign_document_action = QtWidgets.QAction('Firmar Documento PDF', self)
        sign_document_action.triggered.connect(self.sign_document)
        sign_menu.addAction(sign_document_action)

        verify_message_action = QtWidgets.QAction('Verificar Mensaje', self)
        verify_message_action.triggered.connect(self.verify_message)
        verify_menu.addAction(verify_message_action)

        verify_document_action = QtWidgets.QAction('Verificar Documento PDF', self)
        verify_document_action.triggered.connect(self.verify_document)
        verify_menu.addAction(verify_document_action)

        encrypt_message_action = QtWidgets.QAction('Encriptar Mensaje', self)
        encrypt_message_action.triggered.connect(self.encrypt_message)
        encrypt_menu.addAction(encrypt_message_action)

        decrypt_message_action = QtWidgets.QAction('Desencriptar Mensaje', self)
        decrypt_message_action.triggered.connect(self.decrypt_message)
        decrypt_menu.addAction(decrypt_message_action)

        # Área principal
        self.text_area = QtWidgets.QTextEdit()
        self.setCentralWidget(self.text_area)

    def get_user_paths(self):
        user_dir = os.path.join(USERS_DIR, self.username)
        private_key_path = os.path.join(user_dir, 'private_key.pem')
        public_key_path = os.path.join(user_dir, 'public_key.pem')
        cert_path = os.path.join(user_dir, 'cert.pem')
        return private_key_path, public_key_path, cert_path

    def sign_message(self):
        text, ok = QtWidgets.QInputDialog.getMultiLineText(self, 'Firmar Mensaje', 'Ingrese el mensaje:')
        if ok and text:
            private_key_path, _, cert_path = self.get_user_paths()
            key_password, ok_pass = QtWidgets.QInputDialog.getText(self, 'Contraseña', 'Ingrese su contraseña de la llave privada:', QtWidgets.QLineEdit.Password)
            if ok_pass:
                private_key = load_private_key(private_key_path, key_password)
                cert_pem = open(cert_path, 'rb').read()
                algorithm = 'RSA' if isinstance(private_key, rsa.RSAPrivateKey) else 'ECDSA'
                signature = sign_message(private_key, text, algorithm)
                with open('signature.sig', 'wb') as f:
                    f.write(signature)
                with open('message.txt', 'w') as f:
                    f.write(text)
                with open('certificate.pem', 'wb') as f:
                    f.write(cert_pem)
                QtWidgets.QMessageBox.information(self, 'Éxito', 'Mensaje firmado correctamente.')
                logging.info(f"Usuario '{self.username}' firmó un mensaje.")
                self.text_area.setText(f"Mensaje firmado:\n{text}")
            else:
                QtWidgets.QMessageBox.warning(self, 'Error', 'Operación cancelada.')
                logging.warning(f"Usuario '{self.username}' canceló la firma del mensaje.")

    def verify_message(self):
        options = QtWidgets.QFileDialog.Options()
        message_file, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Seleccionar Mensaje', '', 'Text Files (*.txt)', options=options)
        if message_file:
            signature_file, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Seleccionar Firma', '', 'Signature Files (*.sig)', options=options)
            if signature_file:
                cert_file, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Seleccionar Certificado', '', 'Certificate Files (*.pem)', options=options)
                if cert_file:
                    # Leer los archivos
                    with open(message_file, 'r') as f:
                        message = f.read()
                    with open(signature_file, 'rb') as f:
                        signature = f.read()
                    with open(cert_file, 'rb') as f:
                        cert_pem = f.read()
                    # Cargar el certificado y la clave pública
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                    public_key = cert.public_key()
                    # Verificar el certificado con el CA
                    with open(CA_CERT_FILE, 'rb') as f:
                        ca_cert_pem = f.read()
                    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
                    try:
                        ca_cert.public_key().verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            cert.signature_hash_algorithm,
                        )
                    except Exception:
                        QtWidgets.QMessageBox.warning(self, 'Error', 'El certificado del firmante no es válido.')
                        return
                    # Determinar el algoritmo
                    algorithm = 'RSA' if isinstance(public_key, rsa.RSAPublicKey) else 'ECDSA'
                    # Verificar la firma
                    valid = verify_signature(public_key, message, signature, algorithm)
                    if valid:
                        signer_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        QtWidgets.QMessageBox.information(self, 'Éxito', f'La firma es válida. Firmado por: {signer_name}')
                        logging.info(f"Usuario '{self.username}' verificó una firma válida de '{signer_name}'.")
                        self.text_area.setText(f"Mensaje verificado y firmado por {signer_name}:\n{message}")
                    else:
                        QtWidgets.QMessageBox.warning(self, 'Error', 'La firma no es válida.')
                        logging.warning(f"Usuario '{self.username}' verificó una firma no válida.")
                else:
                    QtWidgets.QMessageBox.warning(self, 'Error', 'No se seleccionó un certificado.')
            else:
                QtWidgets.QMessageBox.warning(self, 'Error', 'No se seleccionó un archivo de firma.')
        else:
            QtWidgets.QMessageBox.warning(self, 'Error', 'No se seleccionó un mensaje.')

    def sign_document(self):
        options = QtWidgets.QFileDialog.Options()
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Seleccionar PDF', '', 'PDF Files (*.pdf)', options=options)
        if file_name:
            private_key_path, _, cert_path = self.get_user_paths()
            key_password, ok_pass = QtWidgets.QInputDialog.getText(self, 'Contraseña', 'Ingrese su contraseña de la llave privada:', QtWidgets.QLineEdit.Password)
            if ok_pass:
                try:
                    private_key = load_private_key(private_key_path, key_password)
                    with open(cert_path, 'rb') as f:
                        cert_pem = f.read()
                    output_file = os.path.splitext(file_name)[0] + '_signed.pdf'
                    sign_pdf(file_name, output_file, private_key, cert_pem)
                    QtWidgets.QMessageBox.information(self, 'Éxito', f'Documento firmado correctamente y guardado como {output_file}.')
                    logging.info(f"Usuario '{self.username}' firmó un documento PDF.")
                except Exception as e:
                    QtWidgets.QMessageBox.warning(self, 'Error', f'Error al firmar el documento: {str(e)}')
                    logging.error(f"Error al firmar el documento: {str(e)}")
            else:
                QtWidgets.QMessageBox.warning(self, 'Error', 'Operación cancelada.')
        else:
            QtWidgets.QMessageBox.warning(self, 'Error', 'No se seleccionó un archivo.')

    def verify_document(self):
        options = QtWidgets.QFileDialog.Options()
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Seleccionar PDF', '', 'PDF Files (*.pdf)', options=options)
        if file_name:
            try:
                with open(CA_CERT_FILE, 'rb') as f:
                    ca_cert_pem = f.read()
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
                valid, message = verify_pdf(file_name, ca_cert)
                if valid:
                    QtWidgets.QMessageBox.information(self, 'Éxito', message)
                    logging.info(f"Usuario '{self.username}' verificó un documento firmado.")
                else:
                    QtWidgets.QMessageBox.warning(self, 'Error', message)
                    logging.warning(f"Usuario '{self.username}' verificó un documento no válido.")
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, 'Error', f'Error al verificar el documento: {str(e)}')
                logging.error(f"Error al verificar el documento: {str(e)}")
        else:
            QtWidgets.QMessageBox.warning(self, 'Error', 'No se seleccionó un archivo.')

    def encrypt_message(self):
        recipient_username, ok_user = QtWidgets.QInputDialog.getText(self, 'Encriptar Mensaje', 'Ingrese el nombre de usuario del destinatario:')
        if ok_user and recipient_username:
            message, ok_msg = QtWidgets.QInputDialog.getMultiLineText(self, 'Encriptar Mensaje', 'Ingrese el mensaje:')
            if ok_msg and message:
                # Cargar la clave pública del destinatario
                recipient_public_key_path = os.path.join(USERS_DIR, recipient_username, 'public_key.pem')
                if os.path.exists(recipient_public_key_path):
                    public_key = load_public_key(recipient_public_key_path)
                    encrypted_symmetric_key, iv, ciphertext = encrypt_message(public_key, message)
                    # Guardar los datos
                    with open('encrypted_message.dat', 'wb') as f:
                        f.write(encrypted_symmetric_key + b'||' + iv + b'||' + ciphertext)
                    QtWidgets.QMessageBox.information(self, 'Éxito', 'Mensaje encriptado correctamente.')
                    logging.info(f"Usuario '{self.username}' encriptó un mensaje para '{recipient_username}'.")
                else:
                    QtWidgets.QMessageBox.warning(self, 'Error', 'La clave pública del destinatario no existe.')
            else:
                QtWidgets.QMessageBox.warning(self, 'Error', 'Operación cancelada.')
        else:
            QtWidgets.QMessageBox.warning(self, 'Error', 'Operación cancelada.')

    def decrypt_message(self):
        options = QtWidgets.QFileDialog.Options()
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Seleccionar Mensaje Encriptado', '', 'Data Files (*.dat)', options=options)
        if file_name:
            private_key_path, _, _ = self.get_user_paths()
            key_password, ok_pass = QtWidgets.QInputDialog.getText(self, 'Contraseña', 'Ingrese su contraseña de la llave privada:', QtWidgets.QLineEdit.Password)
            if ok_pass:
                try:
                    private_key = load_private_key(private_key_path, key_password)
                    # Leer los datos
                    with open(file_name, 'rb') as f:
                        data = f.read()
                    encrypted_symmetric_key, iv, ciphertext = data.split(b'||')
                    message = decrypt_message(private_key, encrypted_symmetric_key, iv, ciphertext)
                    QtWidgets.QMessageBox.information(self, 'Mensaje Desencriptado', message)
                    logging.info(f"Usuario '{self.username}' desencriptó un mensaje.")
                    self.text_area.setText(f"Mensaje desencriptado:\n{message}")
                except Exception as e:
                    QtWidgets.QMessageBox.warning(self, 'Error', f'Error al desencriptar el mensaje: {str(e)}')
                    logging.error(f"Error al desencriptar el mensaje: {str(e)}")
            else:
                QtWidgets.QMessageBox.warning(self, 'Error', 'Operación cancelada.')
        else:
            QtWidgets.QMessageBox.warning(self, 'Error', 'No se seleccionó un archivo.')
