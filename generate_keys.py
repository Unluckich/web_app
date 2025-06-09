# web_app/generate_keys.py

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

def generate_rsa_keys():
    # Генерація приватного ключу (PKCS#8)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Серіалізуємо приватний ключ у PEM (PKCS#8, без пароля)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,   # PKCS#8
        encryption_algorithm=serialization.NoEncryption()
    )

    # Генеруємо публічний ключ у форматі SubjectPublicKeyInfo (PKCS#8)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Створюємо папку keys, якщо її немає
    os.makedirs("keys", exist_ok=True)

    # Записуємо ключі у папку keys/
    with open("keys/private_key.pem", "wb") as f:
        f.write(pem_private)
    with open("keys/public_key.pem", "wb") as f:
        f.write(pem_public)

    print("RSA-ключі згенеровані та записані в web_app/keys/")

if __name__ == "__main__":
    generate_rsa_keys()
