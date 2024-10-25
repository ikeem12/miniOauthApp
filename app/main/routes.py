from flask import render_template,session,redirect,url_for
from flask_login import login_required
from . import main
from config import GITHUB_CLIENT_ID

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html')