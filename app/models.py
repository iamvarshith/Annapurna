from datetime import datetime
from app import db, login_manager, app
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    unique_id = db.Column(db.Integer(), unique=True, nullable=False)
    username = db.Column(db.String(60), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(), nullable=False, default='default.jpg')
    permission = db.Column(db.String(20), nullable=False, default='customer')
    email_confirm = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(60), nullable=True, default='lol_google_login')

    def __repr__(self):
        return f"User('{self.unique_id}', '{self.username}', '{self.email}','{self.image_file}','{self.permission}','{self.email_confirm}','{self.password}')"


class Money(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60))
    money = db.Column(db.Integer())

    def __repr__(self):
        return f"Money('{self.name}',{self.money}')"


class Ngo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    org_name = db.Column(db.String(60), nullable=False)
    org_number = db.Column(db.String(60), nullable=False)
    org_website = db.Column(db.String(60))
    org_tax = db.Column(db.String(60))
    org_address = db.Column(db.String(120))
    org_pin = db.Column(db.String(60))
    org_message = db.Column(db.String(600))

    def __repr__(self):
        return f"Ngo('{self.email}', '{self.org_name}', '{self.org_number}','{self.org_website}','{self.org_tax}'," \
               f"'{self.org_adress}','{self.org_pin}','{self.org_message}')"
