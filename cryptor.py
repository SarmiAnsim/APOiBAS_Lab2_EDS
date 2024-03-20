from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Cryptor():
    def __init__(self):
        # Генерация пары ключей при запуске сервера
        self.private_key, self.public_key = self.generate_key_pair()

    # Генерация пары ключей для RSA
    def generate_key_pair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    # Получение сериализованного публичного ключа
    def serialize_public_key(self, public_key: rsa.RSAPublicKey = None) -> bytes:
        if not public_key:
            public_key = self.public_key
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # Десериализация публичного ключа
    def deserialize_public_key(self, serialized_key: bytes):
        return serialization.load_pem_public_key(serialized_key, backend=default_backend())

    # Подписывание сообщения
    def sign_message(self, message: bytes) -> bytes:
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    # Проверка подписи
    def verify_signature(self, public_key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False