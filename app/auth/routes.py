from flask import url_for, request, redirect,session
from app import oauth
from . import auth

@auth.route('/login/<OauthWith>')
def Login(OauthWith):
    redirect_uri = url_for('auth.callback', _external=True)

    if OauthWith == 'google':
        session['oauth_provider'] = 'google'
        return oauth.google.authorize_redirect(redirect_uri)
    else:
        session['oauth_provider'] = 'github'
        return oauth.github.authorize_redirect(redirect_uri)

@auth.route('/callback')
def callback():
    token = None
    if 'google' in session['oauth_provider']:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
        print(user_info)
        session['user'] = {
            'name': user_info['name'],
            'email': user_info['email'],
            'avatar': user_info['picture']
        }
    elif 'github' in session['oauth_provider']:
        token = oauth.github.authorize_access_token()
        user_info = oauth.github.get('https://api.github.com/user').json()
        user_emails = oauth.github.get('https://api.github.com/user/emails').json()
        primary_email = next((email['email'] for email in user_emails if email['primary'] and email['verified']), None)
        session['user'] = {
            'name': user_info['name'],
            'email': primary_email,
            'avatar': user_info['avatar_url']
        }

    return redirect(url_for('main.profile'))

@auth.route('/logout')
def Logout():
    session.pop('user', None)
    return redirect(url_for('main.index'))
