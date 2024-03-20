import socket
import pickle
from cryptor import Cryptor

import uuid

client_uuid = uuid.uuid4()
client_cryptor = Cryptor()

def set_public_key(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(pickle.dumps({
            'client_id': client_uuid,
            'type': 'set_public_key',
            'public_key': client_cryptor.serialize_public_key()
        }))

def send_verify_message(host, port, message: bytes, signature: bytes) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(pickle.dumps({
            'client_id': client_uuid,
            'type': 'verify_signature',
            'message': message,
            'signature': signature
        }))
        status = s.recv(4096)
    return status.decode()


# Получение публичного ключа от сервера
def get_public_key(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(pickle.dumps({'type': 'get_public_key'}))
        serialized_public_key = s.recv(4096)
        public_key = client_cryptor.deserialize_public_key(serialized_public_key)
    return public_key

def get_random_message(host, port) -> tuple[bytes, bytes]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(pickle.dumps({'type': 'random_message'}))
        request = pickle.loads(s.recv(4096))
        message = request['message']
        signature = request['signature']
    return message, signature


if __name__ == "__main__":
    HOST = "localhost"
    PORT = 12345

    input('Enter для выполнения 1 сценария ...')
    # Сценарий 1
    set_public_key(HOST, PORT)
    message = b'Client message'
    result = send_verify_message(HOST, PORT, message, client_cryptor.sign_message(message))
    print(result)

    input('Enter для выполнения 2 сценария ...')
    # Сценарий 2
    public_key = get_public_key(HOST, PORT)
    message, signature = get_random_message(HOST, PORT)
    print(f'Random message is: "{message.decode()}"')
    if client_cryptor.verify_signature(public_key, signature, message):
        print("Signature is valid.")
    else:
        print("Signature is not valid.")

