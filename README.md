# Flask Login Application

A secure Flask application with login/signup functionality using OAuth2, PostgreSQL database, and password salting.

## Features

- User registration and login
- Password hashing with salting
- Google OAuth2 integration
- PostgreSQL database integration
- Secure session management
- Bootstrap-based responsive UI

## Setup Instructions

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up PostgreSQL:
- Install PostgreSQL if not already installed
- Create a new database named 'flask_login_db'
- Update the DATABASE_URL in .env file with your PostgreSQL credentials

4. Set up Google OAuth2:
- Go to Google Cloud Console
- Create a new project
- Enable OAuth2 API
- Create credentials (OAuth 2.0 Client ID)
- Add authorized redirect URIs
- Update GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env file

5. Run the application:
```bash
python app.py
```

The application will be available at http://localhost:5000

## Security Features

- Password hashing using Werkzeug's security functions
- CSRF protection with Flask-WTF
- Secure session management with Flask-Login
- Environment variables for sensitive data
- SQL injection prevention with SQLAlchemy
