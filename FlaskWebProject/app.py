# Python standard libraries
import json
import os
import sqlite3

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
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", None)
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", None)
GITHUB_DISCOVERY_URL = ("https://github.com/login/oauth/authorize")


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
except sqlite3.OperationalError:
    # Assume it's already been created
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
    # Find out what URL to hit for github login
    github_provider_cfg = get_github_provider_cfg()
    authorization_endpoint = github_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for github login and provide
    # scopes that let you retrieve user's profile from github
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    # Get authorization code Github sent back to you
    code = request.args.get("code")
    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    github_provider_cfg = get_github_provider_cfg()
    token_endpoint = github_provider_cfg["token_endpoint"]
    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
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

    
    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from github that gives you the user's profile information,
    # including their github profile image and email
    userinfo_endpoint = github_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    # You want to make sure their email is verified.
    # The user authenticated with github, authorized your
    # app, and now you've verified their email through github!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by github.", 400
    # Create a user in your db with the information provided
    # by github
    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )

    # Doesn't exist? Add it to the database.
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    # Begin user session by logging the user in
    login_user(user)

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
    app.run('localhost', 4449, ssl_context ='adhoc')
