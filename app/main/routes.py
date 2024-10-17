from flask import render_template,session,redirect,url_for
from . import main
from config import GITHUB_CLIENT_ID

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
def profile():
    user = session.get('user')
    if user is None:
        return redirect(url_for('main.index'))
    
    return render_template('profile.html', user=user)