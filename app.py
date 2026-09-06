import os

from dotenv import load_dotenv
from flask import Flask

from models import init_db
from routes_auth import auth_bp
from routes_oauth import oauth_bp


load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        raise RuntimeError('SECRET_KEY must be set')
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    init_db()
    app.register_blueprint(auth_bp)
    app.register_blueprint(oauth_bp)
    return app


app = create_app()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5100)))
