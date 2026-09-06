import base64
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from models import connection
from passwords import hash_password, verify_password


ACCESS_LIFETIME = timedelta(minutes=30)
REFRESH_LIFETIME = timedelta(days=30)


def key_path(name):
    configured = os.environ.get(name)
    if configured:
        return configured
    return os.path.join(os.path.dirname(__file__), 'keys', 'private_key.pem' if name == 'PRIVATE_KEY_PATH' else 'public_key.pem')


def private_key():
    with open(key_path('PRIVATE_KEY_PATH'), 'rb') as key_file:
        return key_file.read()


def public_key():
    with open(key_path('PUBLIC_KEY_PATH'), 'rb') as key_file:
        return key_file.read()


def issue_access_token(user_id, email, client_id):
    now = datetime.now(timezone.utc)
    return jwt.encode({
        'sub': str(user_id),
        'email': email,
        'iat': now,
        'exp': now + ACCESS_LIFETIME,
        'aud': client_id,
    }, private_key(), algorithm='RS256')


def issue_refresh_token(user_id, client_id):
    raw = secrets.token_urlsafe(48)
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO refresh_tokens
            (token_hash, user_id, client_id, expires_at)
            VALUES (%s, %s, %s, %s)''',
            (hash_password(raw), user_id, client_id,
             datetime.now(timezone.utc) + REFRESH_LIFETIME))
    return raw


def find_refresh_token(raw, client_id):
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT id, token_hash, user_id FROM refresh_tokens
            WHERE client_id = %s AND revoked_at IS NULL AND expires_at > NOW()''', (client_id,))
        for token_id, token_hash, user_id in cursor.fetchall():
            if verify_password(token_hash, raw):
                cursor.execute('UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = %s', (token_id,))
                return user_id
    return None


def public_jwk():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(public_key())
    numbers = key.public_numbers()

    def encode(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()

    return {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'auth-service-rs256',
            'n': encode(numbers.n), 'e': encode(numbers.e)}
