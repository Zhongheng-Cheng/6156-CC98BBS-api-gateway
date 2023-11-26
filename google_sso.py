from flask import Flask, redirect, request, session, url_for
import requests
import json

app = Flask(__name__)

# Google console settings
GOOGLE_CLIENT_ID = "848195831750-7mbad191l9mtmh6op61epg30fa6gg4fb.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
REDIRECT_URI = "http://localhost:8000/callback"  # align with the redirect_uri in Google Console

# Google OAuth 2.0
AUTHORIZATION_BASE_URL = 'https://accounts.google.com/o/oauth2/auth'
TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
USER_INFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'

# secret key for Flask program
app.secret_key = 'your_secret_key'


@app.route('/')
def home():
    return 'Welcome to Flask OAuth 2.0 SSO with Google | <a href="http://localhost:8000/login">Log In</a>'


@app.route('/login')
def login():
    authorization_url = f"{AUTHORIZATION_BASE_URL}?client_id={GOOGLE_CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=openid%20email&response_type=code"
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    code = request.args.get('code')
    print(f"code: {code}")

    token_url_params = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    token_response = requests.post(TOKEN_URL, data=token_url_params)
    token_data = token_response.json()
    access_token = token_data.get('access_token')

    user_info_response = requests.get(USER_INFO_URL, headers={'Authorization': f'Bearer {access_token}'})
    user_info = user_info_response.json()

    session['user_info'] = user_info

    return redirect(url_for('profile'))


@app.route('/profile')
def profile():
    user_info = session.get('user_info')
    print(user_info)
    if user_info:
        return f"Welcome! Your email is {user_info['email']}."
    else:
        return "User not authenticated."


if __name__ == '__main__':
    app.run(debug=True, port=8000)