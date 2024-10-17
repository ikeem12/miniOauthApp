from flask import Flask
from authlib.integrations.flask_client import OAuth
from flask_login import LoginManager
from config import *

oauth = OAuth()
login = LoginManager()

def createApp():
    app = Flask(__name__, template_folder='main/templates', static_folder='main/static')
    app.secret_key = SECRET_KEY

    oauth.init_app(app)

    google = oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        access_token_url='https://accounts.google.com/o/oauth2/token',
        client_kwargs={'scope': 'openid profile email'},
        jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
    )

    github = oauth.register(
        name='github',
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        authorize_url='https://github.com/login/oauth/authorize',
        access_token_url='https://github.com/login/oauth/access_token',
        client_kwargs={'scope': 'user user:email'},
    )

    from .auth import auth
    from .main import main

    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(main)

    return app