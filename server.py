import socket
import pickle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptor import Cryptor

server_cryptor = Cryptor()

clients = dict()

def handle_client(conn):
    while True:
        data = conn.recv(4096)
        if not data:
            break
        request = pickle.loads(data)
        if request["type"] == "set_public_key":
            clients[request["client_id"]] = server_cryptor.deserialize_public_key(request["public_key"])
        elif request["type"] == "verify_signature":
            message = request["message"]
            signature = request["signature"]
            if request["client_id"] not in clients:
                conn.sendall(b"Public key required.")
                continue
            if server_cryptor.verify_signature(clients[request["client_id"]], signature, message):
                conn.sendall(b"Signature is valid.")
            else:
                conn.sendall(b"Signature is not valid.")

        elif request["type"] == "get_public_key":
            serialized_public_key = server_cryptor.serialize_public_key()
            conn.sendall(serialized_public_key)
        elif request["type"] == "random_message":
            message = b'Random message'
            signature = server_cryptor.sign_message(message)
            conn.sendall(pickle.dumps({'signature': signature, 'message': message}))


# Запуск сервера
def run_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            print(f"Connection established with {addr}")
            handle_client(conn)
            conn.close()


if __name__ == "__main__":
    HOST = "localhost"
    PORT = 12345
    run_server(HOST, PORT)