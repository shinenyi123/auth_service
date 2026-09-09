from datetime import datetime, timedelta, timezone
import time

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from models import connection, normalize_email
from otp import create_otp, verify_otp
from passwords import hash_password, verify_password


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


def complete_login(user_id, email):
    session.clear()
    session['user_id'] = user_id
    session['email'] = email
    return redirect(url_for('auth.websites'))


@auth_bp.get('/')
def home():
    if session.get('user_id'):
        return redirect(url_for('auth.websites'))
    return redirect(url_for('auth.login_page'))


@auth_bp.get('/login')
def login_page():
    if session.get('user_id'):
        return redirect(url_for('auth.websites'))
    return render_template('login.html')


@auth_bp.post('/login')
def login_submit():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    if login_rate_limited(email):
        return render_template('login.html', error='Too many login attempts. Please try again later.', next_url=request.full_path), 429
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, email, password_hash FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
    if not user or not verify_password(user[2], str(payload.get('password', ''))):
        return render_template(
            'login.html',
            error='Invalid email or password.',
        ), 401
    LOGIN_ATTEMPTS.pop(f'{request.remote_addr}:{email}', None)
    return complete_login(user[0], user[1])


@auth_bp.get('/signup')
def signup_page():
    return render_template('signup.html')


@auth_bp.get('/websites')
def websites():
    if not session.get('user_id'):
        return redirect(url_for('auth.login_page'))

    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT name, base_url
            FROM websites
            WHERE base_url IS NOT NULL
            ORDER BY name''')
        website_rows = cursor.fetchall()

    websites = [{'name': row[0], 'url': row[1]} for row in website_rows if row[0] and row[1]]
    return render_template(
        'websites.html',
        email=session.get('email', ''),
        websites=websites,
    )


@auth_bp.post('/api/signup/request-otp')
def signup_request_otp():
    payload = request_data()
    email = normalize_email(payload.get('email'))
    if not valid_email(email):
        return jsonify({'error': 'Please enter a valid email address.'}), 400
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE email = %s', (email,))
        if cursor.fetchone():
            return jsonify({'error': 'An account with this email already exists.'}), 409
    try:
        create_otp(email, 'signup')
    except ValueError as error:
        return jsonify({'error': str(error)}), 429
    except Exception:
        return jsonify({'error': 'Unable to send verification email.'}), 503
    session['signup_context'] = {'email': email}
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
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO users (email, password_hash, is_verified)
            VALUES (%s, %s, TRUE) RETURNING id''', (email, hash_password(payload['password'])))
        user_id = cursor.fetchone()[0]
    session.pop('signup_verified', None)
    session.pop('signup_context', None)
    session.clear()
    session['user_id'] = user_id
    session['email'] = email
    return jsonify({'message': 'Account created.', 'redirect': url_for('auth.websites')})


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
