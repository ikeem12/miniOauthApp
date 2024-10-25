from flask import url_for, redirect, session, flash
from flask_login import UserMixin, login_user, logout_user
from app import oauth, login,db, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
from app.models import Users, Oauth_tokens
from datetime import datetime,timezone
from dataclasses import dataclass
from typing import Optional
from . import auth
import requests

class User(UserMixin):
    def __init__(self, id, name, email, avatar):
        self.id = id
        self.name = name
        self.email = email
        self.avatar = avatar

    def get_id(self):
        return self.id

@login.user_loader
def load_user(user_id):
    user = Users.query.get(int(user_id))
    if user:
        return User(id=user.id, name=user.name, email=user.email, avatar=user.avatar)
    return None

@auth.route('/login/<OauthWith>')
def Login(OauthWith):
    """ 
    Path to log in with an OAuth provider (Google or GitHub). 
    Args: OauthWith (str): The OAuth provider to be used to log in ('google' or 'github'). 
    Returns: Redirect to the authorization page of the selected provider. 
    """
    redirect_uri = url_for('auth.callback', _external=True)

    if OauthWith == 'google':
        session['oauth_provider'] = OauthWith
        return oauth.google.authorize_redirect(redirect_uri)
    else:
        session['oauth_provider'] = OauthWith
        return oauth.github.authorize_redirect(redirect_uri)
    
@auth.route('/callback')
def callback():
    """
    Callback path to handle the OAuth provider response after authorization. 
    Returns: Result of the OAuth user information handling.
    """
    provider = session.get('oauth_provider')

    if provider in ['google', 'github']:
        user_info, token_info = get_oauth_user_info(provider)
        return handle_oauth_user(user_info, token_info)
    
@dataclass
class OauthTokenInfo:
    """
    Class to store the OAuth token information. 
    Attributes: 
    user (Optional[Users]): The user associated with the token. 
    provider (str): The OAuth provider ('google' or 'github'). 
    access_token (str): The access token. refresh_token (Optional[str]): 
    The refresh token (optional). 
    expires_in (int): Time in seconds until the token expires.
    """
    user: Optional[Users]
    provider: str
    access_token: str
    refresh_token: Optional[str]
    expires_in: int

def get_oauth_user_info(provider):
    try:
        # obtain token
        token_response = oauth.google.authorize_access_token() if provider == 'google' else oauth.github.authorize_access_token()
        # obtain access token
        access_token = token_response.get('access_token')
        # obtain refresh token (GitHub does not provide refresh tokens)
        refresh_token = token_response.get('refresh_token') if provider == 'google' else None

        if provider == 'google':
            # obtain basic user information
            user_info =  oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
            # Change the key 'picture' to 'avatar' to match the GitHub format
            user_info['avatar'] = user_info.pop('picture', None)
            # obtain token expiration time
            expires_in = token_response.get('expires_in')
        elif provider == 'github':
            # obtain basic user information
            user_info = oauth.github.get('https://api.github.com/user').json()
            # obtain emails
            user_emails = oauth.github.get('https://api.github.com/user/emails').json()
            # obtain primary and verified mail
            primary_email = next((email['email'] for email in user_emails if email['primary'] and email['verified']), None)
            # add email
            user_info['email'] = primary_email
            # GitHub does not provide a token expiration time. Setting a default value.
            expires_in = 28800

        # values are added to their respective keys 
        token_info = OauthTokenInfo(
            user=None, 
            provider=provider,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in
        )

        return user_info,token_info
    except Exception as e:
        flash('Error obtaining user information. Please try again.')
        print(f"Error en get_oauth_user_info: {e}")
        return None,None
    
def handle_oauth_user(user_info, token_info):
    """
    Manages the OAuth user: logs in or updates the token as needed. 
    Args: user_info (dict): User information obtained from the OAuth provider. token_info (OauthTokenInfo): OAuth token information. 
    Returns: Redirection to the profile page or to the login page if the token is expired.
    """
    user = get_or_create_user(user_info)
    token_status = handle_oauth_token(user, token_info)

    if token_status is True:
        user_session = User(id=user.id, name=user.name, email=user.email, avatar=user.avatar)
        login_user(user_session)
        return redirect(url_for('main.profile'))
    elif token_status == 'expired':
        return redirect(url_for('auth.Login', OauthWith=token_info.provider))
    elif token_status == 'no refresh':
        return redirect(url_for('main.index'))
    else:
        save_new_oauth_token(user, token_info)

        user_session = User(id=user.id, name=user.name, email=user.email, avatar=user.avatar)
        login_user(user_session)
        return redirect(url_for('main.profile'))
    
def get_or_create_user(user_info):
    """
    Gets a user from the database or creates a new one if it does not exist. 

    Args: user_info (dict): User information obtained from the OAuth provider. 

    Returns: Users: The user found or created.
    """
    try:
        user = Users.query.filter_by(email=user_info['email']).first()
        if user is None:
            new_user = Users(name=user_info.get('name'), email=user_info['email'], avatar=user_info.get('avatar'))
            db.session.add(new_user)
            db.session.commit()
            user = new_user
        return user
    except Exception as e:
        print(f"Error in get or create_user: {e}")
        return None

def save_new_oauth_token(user_info, token_info):
    """
    Stores a new OAuth token in the database. 
    Args: user_info (Users): The user associated to the token. token_info (OauthTokenInfo): OAuth token information.
    """
    new_oauth_token = Oauth_tokens(user_id=user_info.id, provider=token_info.provider, access_token=token_info.access_token, refresh_token=token_info.refresh_token)
    new_oauth_token.generate_expiration_token(duration_seconds=token_info.expires_in)
    db.session.add(new_oauth_token)
    db.session.commit()

def handle_oauth_token(user_info,token_info):
    """
    Handles the OAuth token logic: verifies its validity and updates if necessary. 
    Args: user_info (Users): The user associated with the token. token_info (OauthTokenInfo): OAuth token information. 
    Returns: bool | str: True if the token is valid, 'expired' if it has expired, or 'no refresh' if it cannot be refreshed.
    """
    try:
        oauth_token = Oauth_tokens.query.filter_by(user_id=user_info.id, provider=token_info.provider).first()

        if oauth_token:
            if oauth_token.expires_at.tzinfo is None:
                oauth_token.expires_at = oauth_token.expires_at.replace(tzinfo=timezone.utc)
            
            if token_info.provider == 'google':
                if is_token_valid(oauth_token):
                    return True 
                elif oauth_token.refresh_token:
                    refresh_status = refresh_oauth_token(token_info.provider, oauth_token)
                    return refresh_status
            elif token_info.provider == 'github':
                if is_token_valid(oauth_token):
                    return True
                else:
                    return 'expired'
        return False
    except Exception as e:
        print(f"Error in handle_oauth_token: {e}")

def is_token_valid(oauth_token):
    """ 
    Checks if an OAuth token is valid according to its expiration date. 
    Args: oauth_token (Oauth_tokens): The OAuth token to verify. 
    Returns: bool: True if the token is valid, false otherwise. 
    """
    return oauth_token.expires_at > datetime.now(timezone.utc)

def refresh_oauth_token(provider, oauth_token):
    """
    Refresh the Google access token if necessary. 
    Args: provider (str): The OAuth provider ('google').
    oauth_token (Oauth_tokens): The OAuth token to refresh. 
    Returns: bool | str: True if the refresh was successful, or 'no refresh' if it failed.
    """
    try:
        if provider == 'google':
            token_url = 'https://oauth2.googleapis.com/token'
            payload = {
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'refresh_token': oauth_token.refresh_token,
                'grant_type': 'refresh_token'
            }
            response = requests.post(token_url, data=payload)
            response_data = response.json()

            if 'access_token' in response_data:
                oauth_token.access_token = response_data['access_token']
                oauth_token.generate_expiration_token(duration_seconds=response_data['expires_in'])

                db.session.commit()
                return True
    except Exception as e: 
        print(f"Error al refrescar el token: {e}")
        return 'no refresh'

@auth.route('/logout')
def Logout():
    logout_user()
    return redirect(url_for('main.index'))