import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
PRIVATE_PATH = os.path.join(KEYS_DIR, 'private_key.pem')
PUBLIC_PATH = os.path.join(KEYS_DIR, 'public_key.pem')


def generate_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if os.path.exists(PRIVATE_PATH) or os.path.exists(PUBLIC_PATH):
        print('A key file already exists; refusing to overwrite keys.')
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PRIVATE_PATH, 'wb') as private_file:
        private_file.write(private_bytes)
    with open(PUBLIC_PATH, 'wb') as public_file:
        public_file.write(public_bytes)
    print(f'Generated {PRIVATE_PATH} and {PUBLIC_PATH}')


if __name__ == '__main__':
    generate_keys()
