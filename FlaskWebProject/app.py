# Python standard libraries
import json
import os
import sqlite3
import logging

#Third party imports
from flask import Flask, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

#Internal imports
from test import bp
from db import init_db_command
from user import User

# Configuration
# https://github.com/settings/applications/1299368
GITHUB_CLIENT_ID = os.environ["GITHUB_CLIENT_ID"]
GITHUB_CLIENT_SECRET = os.environ["GITHUB_CLIENT_SECRET"]
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_URL = "https://api.github.com/user"

logging.basicConfig(filename='application_log.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
logging.info("Initializing application...")
# Create an instance of the Flask class that is the WSGI application.
# The first argument is the name of the application module or package,
# typically __name__ when using a single module.
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)

# Naive database setup
try:
    init_db_command()
except sqlite3.OperationalError as e:
    # Assume it's already been created
    logging.error("Exception in initializing db", exc_info=True)
    pass

# OAuth 2 client setup
client = WebApplicationClient(GITHUB_CLIENT_ID)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Flask route decorators map / and /hello to the hello function.
# To add other resources, create functions that generate the page contents
# and add decorators to define the appropriate resource locators for them.

@app.route("/")
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>github Profile Picture:</p>"
            '<img src="{}" alt="Github profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">Github Login</a>'

def get_github_provider_cfg():
    return requests.get(GITHUB_DISCOVERY_URL).json()


@app.route("/login")
def login():
    try:
        # Use library to construct the request for github login and provide
        # scopes that let you retrieve user's profile from github
        request_uri = client.prepare_request_uri(
            GITHUB_AUTH_URL,
            redirect_uri=request.base_url + "/callback",
            scope=["openid", "email", "profile"],
        )
    except Exception as e:
        logging.error("Exception in login", exc_info=True)
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    try:
        # Get authorization code Github sent back to you
        code = request.args.get("code")
       
        # Prepare and send a request to get tokens! Yay tokens!
        token_url, headers, body = client.prepare_token_request(
            GITHUB_TOKEN_URL,
            authorization_response=request.url,
            redirect_url=request.base_url,
            code=code
        )
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET),
        )

        logging.info("token_response",token_response.content)
    
        # Parse the tokens!
        #client.parse_request_body_response(json.dumps(token_response.json()))

        # Now that you have tokens (yay) let's hit the URL
        # from github that gives you the user's profile information,
        # including their github profile image and email
        #uri, headers, body = client.add_token(GITHUB_USERINFO_URL)
        #userinfo_response = requests.get(uri, headers=headers, data=body)
        
        userinfo_response = requests.get(GITHUB_USERINFO_URL+"?"+token_response.content.decode("utf-8") , headers=headers, data=token_response.content)

        if userinfo_response.json().get("name"):
            unique_id = userinfo_response.json()["login"]
            users_email = userinfo_response.json()["email"]
            profile_pic = userinfo_response.json()["avatar_url"]
            users_name = userinfo_response.json()["name"]
        else:
            return "User not available or not verified by github.", 400
        # Create a user in your db with the information provided
        # by github
        user = User(
            id_=unique_id, name=users_name, email=users_email, profile_pic = profile_pic
        )

        # Doesn't exist? Add it to the database.
        if not User.get(unique_id):
            User.create(unique_id, users_name, users_email, profile_pic)

        # Begin user session by logging the user in
        login_user(user)
    except Exception as e:
        logging.error("Exception in login", exc_info=True)
    # Send user back to homepage
    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

if __name__ == '__main__':
    # Run the app server on localhost:4449
    app.register_blueprint(bp, url_prefix ="/test")
    context = ('selfsigned.crt', 'selfsigned.key')#certificate and key files
    app.run('localhost', 4449, ssl_context=context)
