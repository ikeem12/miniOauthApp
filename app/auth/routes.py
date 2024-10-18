from flask import url_for, request, redirect,session
from flask_login import UserMixin, login_user, logout_user
from app import oauth, login
from . import auth

# Simulación de una base de datos de usuarios en memoria
fake_db = {}

class User(UserMixin):
    def __init__(self, id, email, name, avatar):
        self.id = id
        self.email = email
        self.name = name
        self.avatar = avatar

    def get_id(self):
        # Este método devuelve el ID del usuario actual (self.id)
        return self.id

    @staticmethod
    def get(user_id):
        return fake_db.get(user_id)


@login.user_loader
def load_user(user_id):
    # Fetch user from the database by their ID
    return User.get(user_id)

@auth.route('/login/<OauthWith>')
def Login(OauthWith):
    redirect_uri = url_for('auth.callback', _external=True)

    if OauthWith == 'google':
        session['oauth_provider'] = 'google'
        return oauth.google.authorize_redirect(redirect_uri, prompt='select_account')
    else:
        session['oauth_provider'] = 'github'
        return oauth.github.authorize_redirect(redirect_uri)

@auth.route('/callback')
def callback():
    token = None
    if 'google' in session['oauth_provider']:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
        user_id = user_info['sub']

        user = User(id=user_id, email=user_info['email'], name=user_info['name'], avatar=user_info['picture'])
        fake_db[user_id] = user

        # session['user'] = {
        #     'name': user_info['name'],
        #     'email': user_info['email'],
        #     'avatar': user_info['picture']
        # }

    elif 'github' in session['oauth_provider']:
        token = oauth.github.authorize_access_token()
        refresh_token = token.get('refresh_token')

        if refresh_token:
            print(f"Refresh token: {refresh_token}")
        else:
            print("No refresh token received.")

        user_info = oauth.github.get('https://api.github.com/user').json()
        user_emails = oauth.github.get('https://api.github.com/user/emails').json()
        primary_email = next((email['email'] for email in user_emails if email['primary'] and email['verified']), None)
        user_id = str(user_info['id'])

        user = User(id=user_id, email=primary_email, name=user_info['name'], avatar=user_info['avatar_url'])
        fake_db[user_id] = user

        # session['user'] = {
        #     'name': user_info['name'],
        #     'email': primary_email,
        #     'avatar': user_info['avatar_url']
        # }

    login_user(user)

    return redirect(url_for('main.profile'))

@auth.route('/logout')
def Logout():
    logout_user()
    # session.pop('user', None)
    return redirect(url_for('main.index'))
