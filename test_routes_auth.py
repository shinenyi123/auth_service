import os
import unittest
from unittest.mock import MagicMock, patch

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
            ('Student Dashboard', 'https://unused.example.com', 'student-dashboard'),
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
        self.assertIn(b'Student', response.data)
        self.assertIn(b'Dashboard', response.data)
        self.assertIn(b'https://student-dashboard-v2.onrender.com/auth/login', response.data)
        self.assertNotIn(b'https://unused.example.com', response.data)
        self.assertNotIn(b'client_secret', response.data)
        self.assertNotIn(b'access_token', response.data)
        self.assertNotIn(b'refresh_token', response.data)
        self.assertEqual(cursor.parameters, (7,))
        self.assertIn('user_websites', cursor.query)
        self.assertIn('websites', cursor.query)

    def test_websites_hides_student_dashboard_without_authorization(self):
        cursor = FakeCursor([
            ('Habit Tracker', 'https://habit.example.com/auth/login', 'habit-tracker'),
        ])
        app = create_test_app()
        client = app.test_client()
        with client.session_transaction() as session:
            session['user_id'] = 7
            session['email'] = 'student@example.com'

        with patch('routes_auth.connection', return_value=FakeConnection(cursor)):
            response = client.get('/websites')

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'Student Dashboard', response.data)
        self.assertNotIn(b'https://student-dashboard-v2.onrender.com/auth/login', response.data)
        self.assertIn(b'Habit Tracker', response.data)

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

    @patch.dict(os.environ, {'AUTH_SERVICE_API_KEY': 'website-key'})
    @patch('routes_auth.verify_password', return_value=True)
    @patch('routes_auth.connection')
    def test_authentication_returns_minimal_authorized_identity(self, connection, verify_password):
        cursor = MagicMock()
        cursor.fetchone.side_effect = [
            (7, 'student@example.com', 'password-hash', True),
            (1,),
        ]
        database = MagicMock()
        database.__enter__.return_value.cursor.return_value = cursor
        connection.return_value = database

        response = create_test_app().test_client().post(
            '/api/authenticate',
            json={'email': 'student@example.com', 'password': 'password', 'website_slug': 'student-dashboard'},
            headers={'X-Auth-Service-Key': 'website-key'},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {
            'success': True,
            'user': {'id': 7, 'email': 'student@example.com'},
        })
        self.assertNotIn('password_hash', response.json)
        self.assertNotIn('password', response.json)
        self.assertNotIn('client_secret', response.json)
        self.assertEqual(cursor.execute.call_args_list[1].args[1], (7, 'student-dashboard'))
        verify_password.assert_called_once_with('password-hash', 'password')

    @patch.dict(os.environ, {'AUTH_SERVICE_API_KEY': 'website-key'})
    @patch('routes_auth.verify_password', return_value=False)
    @patch('routes_auth.connection')
    def test_authentication_rejects_invalid_credentials_generically(self, connection, verify_password):
        cursor = MagicMock()
        cursor.fetchone.return_value = (7, 'student@example.com', 'password-hash', True)
        database = MagicMock()
        database.__enter__.return_value.cursor.return_value = cursor
        connection.return_value = database

        response = create_test_app().test_client().post(
            '/api/authenticate',
            json={'email': 'student@example.com', 'password': 'wrong', 'website_slug': 'student-dashboard'},
            headers={'X-Auth-Service-Key': 'website-key'},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json, {'success': False, 'error': 'Invalid email or password'})
        self.assertEqual(cursor.execute.call_count, 1)

    @patch.dict(os.environ, {'AUTH_SERVICE_API_KEY': 'website-key'})
    @patch('routes_auth.verify_password', return_value=True)
    @patch('routes_auth.connection')
    def test_authentication_rejects_unauthorized_website(self, connection, verify_password):
        cursor = MagicMock()
        cursor.fetchone.side_effect = [(7, 'student@example.com', 'password-hash', True), None]
        database = MagicMock()
        database.__enter__.return_value.cursor.return_value = cursor
        connection.return_value = database

        response = create_test_app().test_client().post(
            '/api/authenticate',
            json={'email': 'student@example.com', 'password': 'password', 'website_slug': 'other-site'},
            headers={'X-Auth-Service-Key': 'website-key'},
        )

        self.assertEqual(response.status_code, 403)
        self.assertNotIn('user', response.json)

    def test_authentication_requires_internal_key(self):
        with patch.dict(os.environ, {'AUTH_SERVICE_API_KEY': 'website-key'}):
            response = create_test_app().test_client().post('/api/authenticate', json={})
        self.assertEqual(response.status_code, 401)

    @patch('routes_auth.create_otp')
    @patch('routes_auth.connection')
    def test_signup_request_and_verification_flow_remains_available(self, connection, create_otp):
        cursor = FakeCursor(rows=(), row=None)
        connection.return_value = FakeConnection(cursor)
        client = create_test_app().test_client()

        response = client.post('/api/signup/request-otp', json={'email': 'new@example.com'})
        self.assertEqual(response.status_code, 200)
        create_otp.assert_called_once_with('new@example.com', 'signup')

        with patch('routes_auth.verify_otp', return_value=True):
            response = client.post('/api/signup/verify-otp', json={
                'email': 'new@example.com', 'otp_code': '123456',
            })
        self.assertEqual(response.status_code, 200)

    def test_forgot_password_page_remains_available(self):
        response = create_test_app().test_client().get('/forgot-password')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Reset password', response.data)


if __name__ == '__main__':
    unittest.main()
