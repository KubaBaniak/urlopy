from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, SubmitField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from urlop.models import User
from datetime import date
from flask_login import current_user


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=30)])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign in')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken, please try again with different one')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('Email is already taken, please try again with different one')


class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField('Log in')


class LeaveForm(FlaskForm):
    start_date = DateField('Początek urlopu', validators=[DataRequired()])
    end_date = DateField('Koniec urlopu', validators=[DataRequired()])
    display_days_errors = StringField('')
    submit = SubmitField('Wyślij urlop')

    def validate_display_days_errors(self, display_days_errors):
        days = User.query.filter_by(username=current_user.username).first().days_left
        print(self.start_date.data)
        if self.start_date.data < date.today():
            raise ValidationError('You have selected this day or one from the past. Please select an upcoming day')
        if days < (self.end_date.data - self.start_date.data).days:
            raise ValidationError('You have no days left')
        if self.end_date.data < self.start_date.data:
            raise ValidationError('You have selected a current day, or day before your leave. Please select an day after leaving')
        # checks if user is already on a leave on specific day
        user_leaves = User.query.filter_by(username=current_user.username).first()
        for leave in user_leaves.leave:
            if leave.accepted != 1:
                if (leave.start_day.date() < self.start_date.data < leave.end_day.date()
                        or leave.start_day.date() < self.end_date.data < leave.end_day.date()):
                    raise ValidationError('You are already on a leave between {} and {}'.format(leave.start_day.date(), leave.end_day.date()))


class SearchForm(FlaskForm):
    searchText = StringField('Wyszukaj pracownika')
    submitSearch = SubmitField('Znajdź')

