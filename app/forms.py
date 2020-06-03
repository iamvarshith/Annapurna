from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('LOL this is one is taken , better luck next time dude!')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('LOL this is one is taken , better luck next time dude!')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class Porofile_UpdateForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])

    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('LOL this is one is taken , better luck next time dude!')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('LOL this is one is taken , better luck next time dude!')


class MoneyForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    money = IntegerField('Money', validators=[DataRequired()])
    submit = SubmitField('Login')


class NgoForm(FlaskForm):
    email = StringField('name', validators=[DataRequired(), Email()])
    org_name = StringField('org', validators=[DataRequired()])
    org_number = StringField('name', validators=[DataRequired()])
    org_website = StringField('name')
    org_tax = StringField('name')
    org_address = StringField('name' ,validators=[DataRequired()])
    org_pin = StringField('name',validators=[DataRequired()])
    org_message = StringField('name')
    submit = SubmitField('submit')

class Food_donation(FlaskForm):
    food_quantity = StringField('org', validators=[DataRequired()])
    liquid = StringField('org', validators=[DataRequired()])
    address = StringField('org', validators=[DataRequired()])
    submit = SubmitField('donate')