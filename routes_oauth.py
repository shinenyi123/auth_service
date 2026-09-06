import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from models import connection
from passwords import hash_password, verify_password
from tokens import find_refresh_token, issue_access_token, issue_refresh_token, public_jwk


oauth_bp = Blueprint('oauth', __name__)


def json_data():
    return request.get_json(silent=True) or {}


def internal_authorized():
    expected = os.environ.get('INTERNAL_API_KEY', '')
    supplied = request.headers.get('X-Internal-API-Key', '')
    return bool(expected) and hmac.compare_digest(supplied, expected)


def client_record(cursor, client_id):
    cursor.execute('''SELECT client_id, client_secret_hash, website_id, allowed_redirect_uris
        FROM oauth_clients WHERE client_id = %s''', (client_id,))
    return cursor.fetchone()


def valid_client(cursor, client_id, client_secret):
    client = client_record(cursor, client_id)
    return client if client and verify_password(client[1], client_secret) else None


def token_response(user_id, email, client_id):
    return {
        'access_token': issue_access_token(user_id, email, client_id),
        'refresh_token': issue_refresh_token(user_id, client_id),
        'expires_in': 1800,
    }


@oauth_bp.post('/oauth/token')
def exchange_code():
    payload = json_data()
    code = str(payload.get('code', ''))
    client_id = str(payload.get('client_id', ''))
    client_secret = str(payload.get('client_secret', ''))
    redirect_uri = str(payload.get('redirect_uri', ''))
    with connection() as conn:
        cursor = conn.cursor()
        client = valid_client(cursor, client_id, client_secret)
        if not client:
            return jsonify({'error': 'invalid_client'}), 401
        if redirect_uri not in (client[3] or []):
            return jsonify({'error': 'invalid_redirect_uri'}), 400
        cursor.execute('''SELECT ac.id, ac.user_id, ac.redirect_uri, u.email
            FROM auth_codes ac JOIN users u ON u.id = ac.user_id
            WHERE ac.code = %s AND ac.client_id = %s
              AND ac.expires_at > NOW() AND ac.consumed_at IS NULL''', (code, client_id))
        auth_code = cursor.fetchone()
        if not auth_code or auth_code[2] != redirect_uri:
            return jsonify({'error': 'invalid_grant'}), 400
        cursor.execute('UPDATE auth_codes SET consumed_at = NOW() WHERE id = %s', (auth_code[0],))
        return jsonify(token_response(auth_code[1], auth_code[3], client_id))


@oauth_bp.post('/oauth/refresh')
def refresh():
    payload = json_data()
    client_id = str(payload.get('client_id', ''))
    client_secret = str(payload.get('client_secret', ''))
    raw_refresh = str(payload.get('refresh_token', ''))
    with connection() as conn:
        cursor = conn.cursor()
        if not valid_client(cursor, client_id, client_secret):
            return jsonify({'error': 'invalid_client'}), 401
    user_id = find_refresh_token(raw_refresh, client_id)
    if not user_id:
        return jsonify({'error': 'invalid_grant'}), 400
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'invalid_grant'}), 400
    return jsonify(token_response(user_id, user[0], client_id))


@oauth_bp.get('/.well-known/jwks.json')
def jwks():
    return jsonify({'keys': [public_jwk()]})


@oauth_bp.post('/internal/websites')
def create_website():
    if not internal_authorized():
        return jsonify({'error': 'Unauthorized.'}), 401
    payload = json_data()
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO websites (slug, name, base_url)
            VALUES (%s, %s, %s) RETURNING id, slug, name, base_url''',
            (payload.get('slug'), payload.get('name'), payload.get('base_url')))
        row = cursor.fetchone()
    return jsonify({'id': row[0], 'slug': row[1], 'name': row[2], 'base_url': row[3]}), 201


@oauth_bp.post('/internal/oauth-clients')
def create_oauth_client():
    if not internal_authorized():
        return jsonify({'error': 'Unauthorized.'}), 401
    payload = json_data()
    client_id = f'client_{secrets.token_urlsafe(18)}'
    client_secret = secrets.token_urlsafe(36)
    redirect_uris = payload.get('redirect_uris') or []
    if not isinstance(redirect_uris, list) or not all(isinstance(uri, str) for uri in redirect_uris):
        return jsonify({'error': 'redirect_uris must be a list of strings.'}), 400
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO oauth_clients
            (client_id, client_secret_hash, website_id, allowed_redirect_uris)
            VALUES (%s, %s, %s, %s) RETURNING id''',
            (client_id, hash_password(client_secret), payload.get('website_id'), redirect_uris))
        client_id_row = cursor.fetchone()[0]
    return jsonify({'id': client_id_row, 'client_id': client_id, 'client_secret': client_secret}), 201


@oauth_bp.post('/internal/grant-access')
def grant_access():
    if not internal_authorized():
        return jsonify({'error': 'Unauthorized.'}), 401
    payload = json_data()
    with connection() as conn:
        cursor = conn.cursor()
        if payload.get('user_id'):
            user_query = ('id = %s', (payload['user_id'],))
        else:
            user_query = ('email = %s', (str(payload.get('email', '')).strip().lower(),))
        cursor.execute(f'SELECT id FROM users WHERE {user_query[0]}', user_query[1])
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        cursor.execute('''INSERT INTO user_websites (user_id, website_id, role)
            VALUES (%s, %s, %s) ON CONFLICT (user_id, website_id)
            DO UPDATE SET role = EXCLUDED.role''',
            (user[0], payload.get('website_id'), payload.get('role', 'member')))
    return jsonify({'message': 'Access granted.'})
