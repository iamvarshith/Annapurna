from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from oauthlib.oauth2 import WebApplicationClient

from app.paytm import checksum
import requests
import json
import os

# Configuration


app = Flask(__name__)
app.config['SECRET_KEY'] = '17176e02a219512af8df10664e155a71'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
GOOGLE_CLIENT_ID = "289288864052-mqqaf81o3bc4ep74i590iv5qn2vedv70.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = '9Z8jzz_6q-sBaQxz6j_SnuNc'
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

client = WebApplicationClient(GOOGLE_CLIENT_ID)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = u"Please Login to continue"
login_manager.login_message_category = "info"
from app import routes
