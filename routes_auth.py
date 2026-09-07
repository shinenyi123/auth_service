from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
import time
from urllib.parse import urlencode, urlparse, urlunparse

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from models import connection, normalize_email
from otp import create_otp, verify_otp
from passwords import hash_password, verify_password
from tokens import issue_access_token, issue_refresh_token


auth_bp = Blueprint('auth', __name__)
VERIFY_WINDOW = timedelta(minutes=10)
LOGIN_ATTEMPTS = {}
LOGIN_LIMIT = 5
LOGIN_WINDOW = 300


def valid_email(email):
    return '@' in email and '.' in email.rsplit('@', 1)[-1]


def password_error(password):
    return 'Password must be at least 8 characters.' if len(password) < 8 else None


def request_data():
    return request.get_json(silent=True) or request.form.to_dict()


def login_rate_limited(email):
    now = time.monotonic()
    key = f'{request.remote_addr}:{email}'
    attempts = [stamp for stamp in LOGIN_ATTEMPTS.get(key, []) if now - stamp < LOGIN_WINDOW]
    if len(attempts) >= LOGIN_LIMIT:
        LOGIN_ATTEMPTS[key] = attempts
        return True
    attempts.append(now)
    LOGIN_ATTEMPTS[key] = attempts
    return False


def client_context(client_id, redirect_uri):
    if not client_id or not redirect_uri:
        return None
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT oc.website_id, oc.allowed_redirect_uris
            FROM oauth_clients oc WHERE oc.client_id = %s''', (client_id,))
        client = cursor.fetchone()
    if not client or redirect_uri not in (client[1] or []):
        return None
    return {'client_id': client_id, 'redirect_uri': redirect_uri, 'website_id': client[0]}


def redirect_with_code(user_id, email, context, state=''):
    from secrets import token_urlsafe
    from models import connection

    code = token_urlsafe(32)
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO auth_codes
            (code, user_id, client_id, redirect_uri, expires_at)
            VALUES (%s, %s, %s, %s, %s)''',
            (code, user_id, context['client_id'], context['redirect_uri'],
             datetime.now(timezone.utc) + timedelta(seconds=60)))
    query = {'code': code}
    if state:
        query['state'] = state
    parsed = urlparse(context['redirect_uri'])
    return urlunparse(parsed._replace(query=urlencode(query)))


def complete_login(user_id, email, context=None, state=''):
    session.clear()
    session['user_id'] = user_id
    session['email'] = email
    if context:
        return redirect(redirect_with_code(user_id, email, context, state))
    return redirect(url_for('auth.apps'))


def flow_context(payload):
    context = client_context(payload.get('client_id'), payload.get('redirect_uri'))
    if payload.get('client_id') or payload.get('redirect_uri'):
        return context
    return None


@auth_bp.get('/')
def home():
    if session.get('user_id'):
        return redirect(url_for('auth.apps'))
    return redirect(url_for('auth.login_page'))


@auth_bp.get('/login')
def login_page():
    payload = request.args
    if payload.get('client_id') or payload.get('redirect_uri'):
        if not client_context(payload.get('client_id'), payload.get('redirect_uri')):
            return 'Invalid client or redirect URI', 400
    if session.get('user_id'):
        context = client_context(payload.get('client_id'), payload.get('redirect_uri')) if payload.get('client_id') else None
        if context:
            return redirect_with_code(session['user_id'], session['email'], context, payload.get('state', ''))
        return redirect(url_for('auth.apps'))
    return render_template('login.html', next_url=request.full_path)


@auth_bp.post('/login')
def login_submit():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    if login_rate_limited(email):
        return render_template('login.html', error='Too many login attempts. Please try again later.', next_url=request.full_path), 429
    context = flow_context(payload)
    if payload.get('client_id') or payload.get('redirect_uri'):
        if context is None:
            return 'Invalid client or redirect URI', 400
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, email, password_hash FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
    if not user or not verify_password(user[2], str(payload.get('password', ''))):
        return render_template(
            'login.html',
            error='Invalid email or password.',
            client_id=payload.get('client_id', ''),
            redirect_uri=payload.get('redirect_uri', ''),
            state=payload.get('state', ''),
        ), 401
    LOGIN_ATTEMPTS.pop(f'{request.remote_addr}:{email}', None)
    return complete_login(user[0], user[1], context, payload.get('state', ''))


@auth_bp.get('/signup')
def signup_page():
    return render_template('signup.html')


@auth_bp.get('/apps')
def apps():
    if not session.get('user_id'):
        return redirect(url_for('auth.login_page'))

    user_id = session['user_id']
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT DISTINCT ON (w.id)
                w.id, w.name, oc.client_id, oc.allowed_redirect_uris[1]
            FROM user_websites uw
            JOIN websites w ON w.id = uw.website_id
            JOIN oauth_clients oc ON oc.website_id = w.id
            WHERE uw.user_id = %s
              AND COALESCE(array_length(oc.allowed_redirect_uris, 1), 0) > 0
            ORDER BY w.id, oc.id''', (user_id,))
        accessible_rows = cursor.fetchall()
        cursor.execute('''SELECT DISTINCT ON (w.id)
                w.id, w.name, oc.client_id, oc.allowed_redirect_uris[1]
            FROM websites w
            JOIN oauth_clients oc ON oc.website_id = w.id
            WHERE NOT EXISTS (
                SELECT 1 FROM user_websites uw
                WHERE uw.user_id = %s AND uw.website_id = w.id
            )
              AND COALESCE(array_length(oc.allowed_redirect_uris, 1), 0) > 0
            ORDER BY w.id, oc.id''', (user_id,))
        available_rows = cursor.fetchall()

    hub_states = session.get('hub_states', {})

    def app_link(row):
        state = token_urlsafe(32)
        hub_states[state] = {'website_id': row[0], 'created_at': datetime.now(timezone.utc).isoformat()}
        return {
            'name': row[1],
            'login_url': url_for('auth.login_page', client_id=row[2], redirect_uri=row[3], state=state),
        }

    accessible_apps = [app_link(row) for row in accessible_rows]
    available_apps = [app_link(row) for row in available_rows]
    session['hub_states'] = hub_states
    return render_template('apps.html', accessible_apps=accessible_apps, available_apps=available_apps)


@auth_bp.post('/api/signup/request-otp')
def signup_request_otp():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    if not valid_email(email):
        return jsonify({'error': 'Please enter a valid email address.'}), 400
    context = flow_context(payload)
    if payload.get('client_id') or payload.get('redirect_uri'):
        if context is None:
            return jsonify({'error': 'Invalid client or redirect URI.'}), 400
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE email = %s', (email,))
        if cursor.fetchone():
            return jsonify({'error': 'An account with this email already exists.'}), 409
    try:
        create_otp(email, 'signup', context.get('website_id') if context else None)
    except ValueError as error:
        return jsonify({'error': str(error)}), 429
    except Exception:
        return jsonify({'error': 'Unable to send verification email.'}), 503
    session['signup_context'] = {'email': email, 'client_id': payload.get('client_id'), 'redirect_uri': payload.get('redirect_uri'), 'state': payload.get('state', '')}
    return jsonify({'message': 'Verification code sent.'})


@auth_bp.post('/api/signup/verify-otp')
def signup_verify_otp():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    if verify_otp(email, payload.get('otp_code'), 'signup'):
        session['signup_verified'] = {'email': email, 'expires_at': (datetime.now(timezone.utc) + VERIFY_WINDOW).isoformat()}
        return jsonify({'message': 'Email verified.'})
    return jsonify({'error': 'Invalid or expired verification code.'}), 400


@auth_bp.post('/api/signup/set-password')
def signup_set_password():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    verification = session.get('signup_verified') or {}
    expires = datetime.fromisoformat(verification.get('expires_at', '1970-01-01T00:00:00+00:00'))
    if verification.get('email') != email or expires <= datetime.now(timezone.utc):
        return jsonify({'error': 'Please verify your email first.'}), 403
    error = password_error(str(payload.get('password', '')))
    if error:
        return jsonify({'error': error}), 400
    context_data = session.get('signup_context') or {}
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO users (email, password_hash, is_verified)
            VALUES (%s, %s, TRUE) RETURNING id''', (email, hash_password(payload['password'])))
        user_id = cursor.fetchone()[0]
        if context_data.get('client_id'):
            context = client_context(context_data['client_id'], context_data.get('redirect_uri'))
            if context:
                cursor.execute('''INSERT INTO user_websites (user_id, website_id)
                    VALUES (%s, %s) ON CONFLICT (user_id, website_id) DO NOTHING''',
                    (user_id, context['website_id']))
    context = client_context(context_data.get('client_id'), context_data.get('redirect_uri')) if context_data.get('client_id') else None
    session.pop('signup_verified', None)
    session.pop('signup_context', None)
    return complete_login(user_id, email, context, context_data.get('state', ''))


@auth_bp.get('/forgot-password')
def forgot_page():
    return render_template('forgot_password.html')


@auth_bp.post('/api/forgot-password/request-otp')
def forgot_request_otp():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE email = %s', (email,))
        exists = cursor.fetchone() is not None
    if exists:
        try:
            create_otp(email, 'reset_password')
        except ValueError as error:
            return jsonify({'error': str(error)}), 429
        except Exception:
            pass
    return jsonify({'message': 'If the account exists, a verification code will be sent.'})


@auth_bp.post('/api/forgot-password/verify-otp')
def forgot_verify_otp():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    if verify_otp(email, payload.get('otp_code'), 'reset_password'):
        session['reset_verified'] = {'email': email, 'expires_at': (datetime.now(timezone.utc) + VERIFY_WINDOW).isoformat()}
        return jsonify({'message': 'Email verified.'})
    return jsonify({'error': 'Invalid or expired verification code.'}), 400


@auth_bp.post('/api/forgot-password/set-password')
def forgot_set_password():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    verification = session.get('reset_verified') or {}
    expires = datetime.fromisoformat(verification.get('expires_at', '1970-01-01T00:00:00+00:00'))
    if verification.get('email') != email or expires <= datetime.now(timezone.utc):
        return jsonify({'error': 'Please verify your email first.'}), 403
    error = password_error(str(payload.get('new_password', '')))
    if error:
        return jsonify({'error': error}), 400
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password_hash = %s, updated_at = NOW() WHERE email = %s',
                       (hash_password(payload['new_password']), email))
    session.clear()
    return jsonify({'message': 'Password reset. Please log in.', 'redirect': url_for('auth.login_page')})


@auth_bp.post('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login_page'))
