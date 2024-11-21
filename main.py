# main.py
import sys
import os
from PyQt5 import QtWidgets
from gui import LoginWindow
from pki import create_ca
from logging_config import setup_logging
from config import CA_CERT_FILE, CA_KEY_FILE

def main():
    # Configurar logging
    setup_logging()

    # Crear CA si no existe
    if not (os.path.exists(CA_CERT_FILE) and os.path.exists(CA_KEY_FILE)):
        create_ca()

    app = QtWidgets.QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
