from . import db
from datetime import datetime,timedelta,timezone

class Users(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    avatar = db.Column(db.TEXT, nullable=False)

    def __init__(self, name, email,avatar):
        self.name = name
        self.email = email
        self.avatar = avatar

class Oauth_tokens(db.Model):
    __tablename__ = 'oauth_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    provider = db.Column(db.String(80), nullable=False)
    access_token = db.Column(db.String(1024), unique=True, nullable=False)
    refresh_token = db.Column(db.String(1024), unique=True)
    expires_at = db.Column(db.TIMESTAMP, nullable=False)

    def __init__(self, user_id, provider, access_token, refresh_token=None):
        self.user_id = user_id
        self.provider = provider
        self.access_token = access_token
        self.refresh_token = refresh_token

    def generate_expiration_token(self, duration_seconds):
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)