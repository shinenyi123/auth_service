import os
from contextlib import contextmanager

from dotenv import load_dotenv
from psycopg2.pool import ThreadedConnectionPool


load_dotenv()
_pool = None


def database_url():
    value = os.environ.get('DATABASE_URL')
    if not value:
        raise RuntimeError('DATABASE_URL must be set')
    return value.replace('postgres://', 'postgresql://', 1)


def get_pool():
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(1, 10, dsn=database_url())
    return _pool


@contextmanager
def connection():
    conn = get_pool().getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        get_pool().putconn(conn)


def normalize_email(email):
    return str(email or '').strip().lower()


def init_db():
    with connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'users'""")
        user_columns = {row[0] for row in cursor.fetchall()}
        if user_columns and 'gmail' in user_columns and 'email' not in user_columns:
            cursor.execute('ALTER TABLE users RENAME COLUMN gmail TO email')
            user_columns.remove('gmail')
            user_columns.add('email')
        cursor.execute('''CREATE TABLE IF NOT EXISTS users
            (id SERIAL PRIMARY KEY,
             email TEXT UNIQUE NOT NULL,
             password_hash TEXT NOT NULL,
             is_verified BOOLEAN NOT NULL DEFAULT FALSE,
             created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
             updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''')
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()")
        cursor.execute('''CREATE TABLE IF NOT EXISTS websites
            (id SERIAL PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
             base_url TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_websites
            (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
             website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
             role TEXT NOT NULL DEFAULT 'member', granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
             UNIQUE(user_id, website_id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS otp_codes
            (id SERIAL PRIMARY KEY, email TEXT NOT NULL,
             otp_hash TEXT NOT NULL,
             purpose TEXT NOT NULL CHECK (purpose IN ('signup', 'reset_password')),
             website_id INTEGER REFERENCES websites(id) ON DELETE SET NULL,
             expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ,
             created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''')
        cursor.execute("""SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'otp_codes'""")
        otp_columns = {row[0] for row in cursor.fetchall()}
        if otp_columns and 'gmail' in otp_columns and 'email' not in otp_columns:
            cursor.execute('ALTER TABLE otp_codes RENAME COLUMN gmail TO email')
        if otp_columns and 'otp_code' in otp_columns and 'otp_hash' not in otp_columns:
            cursor.execute('ALTER TABLE otp_codes RENAME COLUMN otp_code TO otp_hash')
        cursor.execute("ALTER TABLE otp_codes ADD COLUMN IF NOT EXISTS website_id INTEGER REFERENCES websites(id) ON DELETE SET NULL")
        cursor.execute("ALTER TABLE otp_codes ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ")
        cursor.execute('''CREATE TABLE IF NOT EXISTS oauth_clients
            (id SERIAL PRIMARY KEY, client_id TEXT UNIQUE NOT NULL,
             client_secret_hash TEXT NOT NULL,
             website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
             allowed_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
             created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_codes
            (id SERIAL PRIMARY KEY, code TEXT UNIQUE NOT NULL,
             user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
             client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
             expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS refresh_tokens
            (id SERIAL PRIMARY KEY, token_hash TEXT NOT NULL,
             user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
             client_id TEXT, expires_at TIMESTAMPTZ NOT NULL,
             revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_websites_pair ON user_websites(user_id, website_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_otp_email_purpose ON otp_codes(email, purpose)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_otp_expires ON otp_codes(expires_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON auth_codes(code)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_hash)')
