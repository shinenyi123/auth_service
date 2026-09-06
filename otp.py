import secrets
from datetime import datetime, timedelta, timezone

from email_service import send_otp_email
from models import connection, normalize_email
from passwords import hash_password, verify_password


OTP_LIFETIME = timedelta(minutes=10)
OTP_COOLDOWN = timedelta(seconds=60)


def cleanup_expired(cursor):
    cursor.execute('DELETE FROM otp_codes WHERE expires_at <= NOW() OR consumed_at IS NOT NULL')


def create_otp(email, purpose, website_id=None):
    email = normalize_email(email)
    code = f'{secrets.randbelow(1000000):06d}'
    with connection() as conn:
        cursor = conn.cursor()
        cleanup_expired(cursor)
        cursor.execute('''SELECT created_at FROM otp_codes
            WHERE email = %s AND purpose = %s AND consumed_at IS NULL
            ORDER BY created_at DESC LIMIT 1''', (email, purpose))
        recent = cursor.fetchone()
        if recent and recent[0].replace(tzinfo=timezone.utc) > datetime.now(timezone.utc) - OTP_COOLDOWN:
            raise ValueError('Please wait 60 seconds before requesting another code.')
        cursor.execute('''INSERT INTO otp_codes
            (email, otp_hash, purpose, website_id, expires_at)
            VALUES (%s, %s, %s, %s, %s)''',
            (email, hash_password(code), purpose, website_id,
             datetime.now(timezone.utc) + OTP_LIFETIME))
    send_otp_email(email, code, purpose)


def verify_otp(email, code, purpose):
    email = normalize_email(email)
    with connection() as conn:
        cursor = conn.cursor()
        cleanup_expired(cursor)
        cursor.execute('''SELECT id, otp_hash FROM otp_codes
            WHERE email = %s AND purpose = %s AND consumed_at IS NULL
              AND expires_at > NOW()
            ORDER BY created_at DESC LIMIT 1''', (email, purpose))
        row = cursor.fetchone()
        if not row or not verify_password(row[1], str(code or '').strip()):
            return False
        cursor.execute('UPDATE otp_codes SET consumed_at = NOW() WHERE id = %s', (row[0],))
        return True
