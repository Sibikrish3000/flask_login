import os
from dotenv import load_dotenv

# Load the environment variables from .env file
load_dotenv(dotenv_path='.env')

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'BLACK_SWORDSMAN' # Secret key for token generation
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:admin@127.0.0.1:5432/flask_login_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'  # Example SMTP server
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')  # Your email
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  # Your email password
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME')
    # OAuth 2.0 Config
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', None)
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', None)
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise ValueError("Missing Google OAuth credentials. Please check your .env file.")
