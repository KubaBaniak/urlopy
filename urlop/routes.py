import datetime

from flask import render_template, redirect, url_for, request, flash, abort
from flask_login import login_user, current_user, logout_user, login_required
from urlop import app, db, bcrypt
from urlop.models import User, Leave
from urlop.forms import LoginForm, RegisterForm, LeaveForm, SearchForm
import pandas as pd
from flask_bcrypt import Bcrypt
from datetime import date


# checking if the day is between friday and sunday and skipping if so
def calculate_days(start_date, end_date):
    delta = datetime.timedelta(days=1)
    days = 0
    while start_date <= end_date:
        # if day_off(start_date): funkcja z ifami ktora sprawdza czy to jest dzien wolny od pracy tam jest ich nw ile
        #     pass
        days = days + 1 if start_date.isoweekday() <= 5 else days
        start_date += delta
    return days

@app.route('/')
def index():
    return render_template('index.html', title='Strona główna')


# Dodaj ze tylko admin moze dodawac ludzi z tej strony, reszta ma error
@app.route('/register', methods=['GET', 'POST'])
def register():
    # if not current_user.is_authenticated or current_user.role != 'Admin':
    #     abort(404, description='You have no permission to create an account')
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode()
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        # do dodania admina
        # user = User(username=form.username.data, email=form.email.data, password=hashed_password, role='Admin')
        db.session.add(user)
        db.session.commit()
        flash('Pomyślnie zarejestrowanu użytkownika', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('leave'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            # w przypadku gdy wejdziemy na account niezalogowani i po
            # zalogowaniu chcielibysmy zeby nas przenioslo tam
            # gdzie mielismy wejc
            next_page = request.args.get('next')
            flash('Pomyślne logowanie', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Logowanie nieudane. Sprawdź email i hasło', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('Wylogowano', 'warning')
    return redirect(url_for('index'))


@app.route('/leave/<string:name>', methods=['POST', 'GET'])
def leave(name):
    form = LeaveForm()
    form_search = SearchForm()

    if current_user.role == 'Admin':
        leaves = Leave.query.all()
    else:
        leaves = User.query.filter_by(username=current_user.username).first().leave

    if form_search.validate_on_submit() and form_search.searchText.data:
        if User.query.filter_by(username=form_search.searchText.data.strip()).first() is None:
            leaves = Leave.query.all()
            flash('Nie ma takiego pracownika', 'danger')
        else:
            flash('{} znaleziony'.format(form_search.searchText.data), 'success')
            leaves = User.query.filter_by(username=form_search.searchText.data.strip()).first().leave
        return render_template('leave.html',
                               form=form,
                               leaves=leaves,
                               title=name,
                               form_search=form_search)
    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data
        leave = Leave(start_day=start_date, end_day=end_date, user=current_user)
        db.session.add(leave)
        db.session.commit()
        return redirect(url_for('leave', name=current_user.username))
    return render_template('leave.html', form=form, form_search=form_search, leaves=leaves, title=name)


@app.route('/clear')
def clear():
    Leave.query.delete()
    user = User.query.filter_by(username=current_user.username).first()
    user.days_left = 26
    db.session.commit()
    return redirect(url_for('leave', name=current_user.username))


@app.route('/delete-leave/<int:leave_id>', methods=['GET', 'POST'])
def delete_leave(leave_id):
    leave_list = Leave.query.filter_by(id=leave_id)
    leave = leave_list.first()

    leave.user.days_left = leave.user.days_left + calculate_days(leave.start_day, leave.end_day)
    # leave.user.days_left += abs(leave.start_day - leave.end_day).days
    leave_list.delete()
    db.session.commit()
    return redirect(url_for('leave', name=current_user.username))


@app.route('/change-accept/<int:leave_id>')
def change_accept(leave_id):
    leave = Leave.query.filter_by(id=leave_id).first()
    start_date = leave.start_day
    end_date = leave.end_day
    user = User.query.filter_by(username = leave.user.username).first_or_404()

    if leave.accepted:
        user.days_left = user.days_left + calculate_days(start_date, end_date)
    else:
        user.days_left = user.days_left - calculate_days(start_date, end_date)
    leave.accepted = not leave.accepted
    db.session.commit()
    print(1)
    return redirect(url_for('leave', name=current_user.username))


@app.errorhandler(404)
def page_not_found(e):
    return e, 404





# def to_dict(row):
#     if row is None:
#         return None
#     rtn_dict = dict()
#     keys = row.__table__.columns.keys()
#     for key in keys:
#         rtn_dict[key] = getattr(row, key)
#     return rtn_dict
#
#
# @app.route('/excel', methods=['GET', 'POST'])
# def exportexcel():
#     data = User.query.all()
#     data_list = [to_dict(item) for item in data]
#     df = pd.DataFrame(data_list)
#     filename = app.config['UPLOAD_FOLDER']+"/excel_database.xlsx"
#     print("Filename: "+filename)
#
#     writer = pd.ExcelWriter(filename)
#     df.to_excel(writer, sheet_name='Registrados')
#     writer.save()
#     return redirect('index')