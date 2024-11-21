# secure_comm.py
import ssl
import socket

def create_tls_context(certfile, keyfile, cafile):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.load_verify_locations(cafile=cafile)
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def secure_server(host, port, context):
    bindsocket = socket.socket()
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    while True:
        newsocket, fromaddr = bindsocket.accept()
        conn = context.wrap_socket(newsocket, server_side=True)
        try:
            data = conn.recv(1024)
            print(f"Mensaje recibido: {data.decode()}")
            conn.send(b"Mensaje recibido de forma segura.")
        finally:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

def secure_client(host, port, context, message):
    sock = socket.socket()
    conn = context.wrap_socket(sock, server_hostname=host)
    conn.connect((host, port))
    conn.send(message.encode())
    data = conn.recv(1024)
    print(f"Respuesta del servidor: {data.decode()}")
    conn.close()
