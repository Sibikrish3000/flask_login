from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import requests
from config import Config
from urllib.parse import quote, urlencode

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
print(app.config['GOOGLE_CLIENT_ID'])
print(app.config['GOOGLE_CLIENT_SECRET'])
mail =Mail(app)
# Serializer to generate and validate the reset token
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])




# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))  # Increased from 128 to 256
    oauth_provider = db.Column(db.String(20))
    oauth_id = db.Column(db.String(100))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Routes

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset_request():
    if request.method == 'POST':
        user_input = request.form['email_or_username'].lower()

        # Check if the input is an email or username
        user = User.query.filter((User.email == user_input) | (User.username == user_input)).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')  # Generate reset token
            reset_url = url_for('password_reset', token=token, _external=True)  # Password reset URL

            # Send the email with the password reset link
            msg = Message('Password Reset Request', recipients=[user.email])
            msg.body = f"To reset your password, click the following link: {reset_url}"
            mail.send(msg)

            flash('Password reset link has been sent to your email.', 'info')
            return redirect(url_for('login'))  # Redirect after sending the reset email
        flash('No user found with that email address.', 'warning')
    return render_template('password_reset_request.html')


@app.route('/password_reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    try:
        # Confirm the token is valid and has not expired
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # max_age is 1 hour
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        print(new_password)
        user.set_password(new_password)  # Hash and store the new password
        db.session.commit()
        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('password_reset.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email'].lower()
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    # Google's OAuth 2.0 Server URL
    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    
    # Parameters for the OAuth request
    params = {
        'client_id': app.config['GOOGLE_CLIENT_ID'],
        'redirect_uri': url_for('google_callback', _external=True),
        'response_type': 'code',
        'scope': 'openid email profile',
        'prompt': 'select_account',
        'access_type': 'offline'  # Add this for refresh token
    }
    
    # Print debug information
    print(f"Google Auth URL Parameters: {params}")
    
    # Redirect user to Google's OAuth 2.0 server
    auth_url = f"{google_auth_url}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/login/google/callback')
def google_callback():
    if 'error' in request.args:
        error = request.args.get('error')
        print(f"Google OAuth Error: {error}")
        flash(f'Authentication failed: {error}')
        return redirect(url_for('login'))

    # Get authorization code from URL parameters
    code = request.args.get('code')
    if not code:
        print("No authorization code received")
        flash('Authentication failed: No authorization code received')
        return redirect(url_for('login'))

    # Exchange authorization code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        'code': code,
        'client_id': app.config['GOOGLE_CLIENT_ID'],
        'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
        'redirect_uri': url_for('google_callback', _external=True),
        'grant_type': 'authorization_code'
    }
    
    print(f"Token Request Data: {token_data}")
    
    try:
        token_response = requests.post(token_url, data=token_data)
        token_response.raise_for_status()  # Raise an error for bad status codes
    except requests.exceptions.RequestException as e:
        print(f"Token Request Error: {str(e)}")
        print(f"Token Response: {token_response.text if 'token_response' in locals() else 'No response'}")
        flash('Failed to get access token. Please try again.')
        return redirect(url_for('login'))
    
    # Get user info using access token
    try:
        access_token = token_response.json().get('access_token')
        userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        userinfo_response = requests.get(
            userinfo_url,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        userinfo_response.raise_for_status()
        userinfo = userinfo_response.json()
    except requests.exceptions.RequestException as e:
        print(f"User Info Request Error: {str(e)}")
        flash('Failed to get user information. Please try again.')
        return redirect(url_for('login'))
    
    try:
        # Check if user exists
        user = User.query.filter_by(email=userinfo['email']).first()
        if not user:
            # Create new user
            user = User(
                username=userinfo.get('name', userinfo['email'].split('@')[0]),
                email=userinfo['email'],
                oauth_provider='google',
                oauth_id=userinfo['sub']
            )
            db.session.add(user)
            db.session.commit()
        
        # Log in the user
        login_user(user)
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Database Error: {str(e)}")
        flash('Failed to create or login user. Please try again.')
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email'].lower()
        if User.query.filter_by(email=email).first() or User.query.filter_by(username=request.form['username']).first():
            flash('Email or username already registered')
            return redirect(url_for('signup'))
        
        user = User(
            username=request.form['username'],
            email=email
        )
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
