from flask import Flask, redirect, request, session, url_for
import requests
import json
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)

# Google console settings
GOOGLE_CLIENT_ID = "848195831750-7mbad191l9mtmh6op61epg30fa6gg4fb.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_REDIRECT_URI = "http://localhost:8000/google-sso-callback"  # align with the redirect_uri in Google Console

# Google OAuth 2.0
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
GOOGLE_USER_INFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'

# JWT
# to get a string like this run: openssl rand -hex 32
SECRET_KEY = "fa1c22f6048073de46d8623e789575ab17ee7b0e2b4ff3116283578255a30097"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# secret key for Flask app
app.secret_key = 'your_secret_key'


@app.route('/')
def home():
    return 'Welcome to Flask OAuth 2.0 SSO with Google | <a href="http://localhost:8000/login">Log In</a>'


@app.route('/login')
def login():
    authorization_url = f"{GOOGLE_AUTH_URL}?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&scope=openid%20email&response_type=code"
    return redirect(authorization_url)


@app.route('/google-sso-callback')
def google_sso_callback():
    code = request.args.get('code')
    print(f"code: {code}")

    token_url_params = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    token_response = requests.post(GOOGLE_TOKEN_URL, data=token_url_params)
    token_data = token_response.json()
    access_token = token_data.get('access_token')

    user_info_response = requests.get(GOOGLE_USER_INFO_URL, headers={'Authorization': f'Bearer {access_token}'})
    user_info = user_info_response.json()

    session['user_info'] = user_info

    return redirect(url_for('profile'))


@app.route('/profile')
def profile():
    user_info = session.get('user_info')
    print(user_info)
    if user_info:
        # return f"Welcome! Your email is {user_info['email']}."
        return create_access_token(
            data={"sub": user_info['email']},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
    return "User not authenticated."
    

def create_access_token(data: dict, expires_delta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    token = jwt.encode(payload=to_encode, 
                             key=SECRET_KEY, 
                             algorithm=ALGORITHM)
    return to_encode


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8000)