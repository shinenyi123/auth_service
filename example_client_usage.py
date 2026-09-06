"""Reference integration for a future website using this Auth Service."""

from urllib.parse import urlencode

import jwt
import requests


AUTH_SERVICE = 'https://auth.example.com'
CLIENT_ID = 'client_from_internal_registration'
CLIENT_SECRET = 'store-this-server-side-only'
CALLBACK_URL = 'https://student.example.com/auth/callback'


def login_url(state):
    return f'{AUTH_SERVICE}/login?' + urlencode({
        'client_id': CLIENT_ID,
        'redirect_uri': CALLBACK_URL,
        'state': state,
    })


def exchange_callback_code(code):
    response = requests.post(f'{AUTH_SERVICE}/oauth/token', json={
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': CALLBACK_URL,
    }, timeout=10)
    response.raise_for_status()
    return response.json()


def verify_access_token(access_token, jwks_client):
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)
    return jwt.decode(
        access_token,
        signing_key.key,
        algorithms=['RS256'],
        audience=CLIENT_ID,
    )


# Flask-style callback sketch:
# @app.get('/auth/callback')
# def auth_callback():
#     tokens = exchange_callback_code(request.args['code'])
#     claims = verify_access_token(tokens['access_token'], cached_jwks_client)
#     session['auth_claims'] = claims
#     session['refresh_token'] = tokens['refresh_token']
#     return redirect('/')
#
# Fetch and cache JWKS periodically:
# from jwt import PyJWKClient
# cached_jwks_client = PyJWKClient(f'{AUTH_SERVICE}/.well-known/jwks.json')
