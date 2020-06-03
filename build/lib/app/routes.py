import json
import os
import random
from flask import Flask, render_template, url_for, flash, redirect, request, jsonify
from app import app, db, bcrypt, login_manager, client
from app.forms import RegistrationForm, LoginForm
from app.models import User
from flask_login import login_user, current_user, logout_user, login_required
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from oauthlib.oauth2 import WebApplicationClient
import requests

GOOGLE_CLIENT_ID = "289288864052-mqqaf81o3bc4ep74i590iv5qn2vedv70.apps.googleusercontent.com"

GOOGLE_CLIENT_SECRET = '9Z8jzz_6q-sBaQxz6j_SnuNc'
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

sq = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# @login_manager.unauthorized_handler
# def unauthorized():
#     return "You must be logged in to access this content.", 403


@app.route('/')
@app.route('/home')
def home():
    if current_user.is_authenticated:
        return render_template('index.html')
    else:
        flash('Login to go to Home page !', 'warning')
        return redirect(url_for('login'))


@app.route('/about')
@login_required
def about():
    if current_user.is_authenticated:
        return render_template('about.html')
    else:
        flash('Login to go to Home page !', 'warning')
        return redirect(url_for('login'))


@app.route("/register", methods=['GET', 'POST'])
@app.route("/join-us/individual", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if form.validate_on_submit():

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        unique_id = (random.randint(100000000000, 10000000000000))

        token = sq.dumps(form.email.data, salt="itstosaltytonothavesaltinthesaltlake")

        user = User(unique_id=unique_id, username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        url = "www.annapurna.tech/confirm_email/" + token
        requests.post("https://api.mailgun.net/v3/support.annapurna.tech/messages",
                      auth=("api", "221bffe3a7b94d381f7e3ff66c3e7332-7fba8a4e-e87281bf"),
                      data={"from": "Annapurna <noreply@support.annapurna.tech>",
                            "to": [form.email.data],
                            "subject": "Registers For Annapurna",
                            # "text": "Please click the link {}".format(url),
                            "template": "userregisteremail",
                            "h:X-Mailgun-Variables": json.dumps({"url": url})

                            })
        flash(f'An verification Email has sent to {form.email.data}!', 'success')
        return redirect(url_for('login'))
    else:

        return render_template('register.html', title='Register', form=form)


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = sq.loads(token, salt="itstosaltytonothavesaltinthesaltlake", max_age=36000)
    except BadTimeSignature:
        return "404"
    except SignatureExpired:
        return "404"
    user = User.query.filter_by(email=email).first
    user().email_confirm = True
    email_email = user().email
    db.session.add(user())
    db.session.commit()
    requests.post("https://api.mailgun.net/v3/support.annapurna.tech/messages",
                  auth=("api", "221bffe3a7b94d381f7e3ff66c3e7332-7fba8a4e-e87281bf"),
                  data={"from": "Annapurna <noreply@support.annapurna.tech>",
                        "to": [email_email],
                        "subject": "Welcome to annapurna {}".format(user().username),
                        # "text": "Please click the link {}".format(url),
                        "template": "welcome",
                        "h:X-Mailgun-Variables": json.dumps({"sitelink": "https://www.annapurna.tech"})

                        })
    return render_template(url_for('login'))


@app.route("/login/google")
def login_google():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri='http://localhost:5000/login/google/callback',
        scope=["openid", "email", "profile"],
        prompt="select_account",

    )
    return redirect(request_uri)


@app.route("/login/google/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that we have tokens (yay) let's find and hit URL
    # from Google that gives you user's profile information,
    # including their Google Profile Image and Email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # We want to make sure their email is verified.
    # The user authenticated with Google, authorized our
    # app, and now we've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]

    else:
        return "User email not available or not verified by Google.", 400

    # we can now insert the incoming data into the db
    user = User.query.filter_by(email=users_email).first()
    if user is None:
        user = User(unique_id=unique_id, username=users_name, email=users_email, image_file=picture)

        db.session.add(user)
        db.session.commit()

        requests.post("https://api.mailgun.net/v3/support.annapurna.tech/messages",
                      auth=("api", "221bffe3a7b94d381f7e3ff66c3e7332-7fba8a4e-e87281bf"),
                      data={"from": "Annapurna <noreply@support.annapurna.tech>",
                            "to": [users_email],
                            "subject": "Welcome to annapurna {}".format(user.username),
                            # "text": "Please click the link {}".format(url),
                            "template": "welcome",
                            "h:X-Mailgun-Variables": json.dumps({"sitelink": "https://www.annapurna.tech"})

                            })
        login_user(user)
        return redirect(url_for('home'))
    else:
        login_user(user)

        return redirect(url_for('home'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.email_confirm != True:
                flash('Bro plox activate Bro !', 'success')
                return render_template('login.html', title='login', form=form)
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))

        else:
            flash("unsucessful login", 'danger')

    return render_template('login.html', title='login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/account")
@login_required
def account():
    return render_template('account.html')


@app.route("/password_reset/<token>")
def password_reset():
    return "comingsoon"


@app.route("/donate")
def donate():
    return "coming Soon"


@app.route("/donate/food")
def donate_food():
    return "coming Soon"


@app.route("/donate/fund")
def donate_fund():
    return "coming Soon"


@app.route("/join-us")
def join_us():
    return "coming Soon"


@app.route("/join-us/ngo")
def join_ngo():
    return "comingsoon"


@app.route("/contact-us")
def contactus():
    return "comingsoon"


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()
