import unittest
from unittest.mock import patch

from flask import Flask

from routes_auth import auth_bp


class FakeCursor:
    def __init__(self, rows=(), row=None):
        self.rows = rows
        self.row = row
        self.query = None
        self.parameters = None

    def execute(self, query, parameters=None):
        self.query = query
        self.parameters = parameters

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_instance = cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def cursor(self):
        return self.cursor_instance


def create_test_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-secret'
    app.register_blueprint(auth_bp)
    return app


class WebsitesRouteTests(unittest.TestCase):
    def test_websites_redirects_unauthenticated_users(self):
        client = create_test_app().test_client()

        response = client.get('/websites')

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/login')

    def test_websites_shows_only_current_users_authorized_websites(self):
        cursor = FakeCursor([
            ('Student Dashboard', 'https://students.example.com/auth/login'),
        ])
        app = create_test_app()
        client = app.test_client()
        with client.session_transaction() as session:
            session['user_id'] = 7
            session['email'] = 'student@example.com'

        with patch('routes_auth.connection', return_value=FakeConnection(cursor)):
            response = client.get('/websites')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'student@example.com', response.data)
        self.assertIn(b'Student Dashboard', response.data)
        self.assertIn(b'https://students.example.com/auth/login', response.data)
        self.assertNotIn(b'client_secret', response.data)
        self.assertNotIn(b'access_token', response.data)
        self.assertNotIn(b'refresh_token', response.data)
        self.assertEqual(cursor.parameters, (7,))
        self.assertIn('user_websites', cursor.query)
        self.assertIn('websites', cursor.query)

    def test_successful_login_redirects_to_websites(self):
        cursor = FakeCursor(row=(7, 'student@example.com', 'password-hash'))
        app = create_test_app()
        client = app.test_client()
        with patch('routes_auth.connection', return_value=FakeConnection(cursor)), \
                patch('routes_auth.verify_password', return_value=True):
            response = client.post('/login', data={'email': 'student@example.com', 'password': 'password'})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/websites')
        with client.session_transaction() as session:
            self.assertEqual(session['user_id'], 7)


if __name__ == '__main__':
    unittest.main()