import datetime

from flask import render_template, redirect, url_for, request, flash, abort, send_file
from flask_login import login_user, current_user, logout_user, login_required
from urlop import app, db, bcrypt, mail
from urlop.models import User, Leave
from urlop.forms import LoginForm, RegisterForm, LeaveForm, SearchForm
from flask_mail import Message
from threading import Thread
import pandas as pd
import os

# checking if the day is between friday and sunday and skipping if so
def calculate_days(start_date, end_date):
    delta = datetime.timedelta(days=1)
    days = 0
    while start_date <= end_date:
        # if day_off(start_date): funcakcja z ifami ktora sprawdza czy to jest dzien wolny od pracy tam jest ich nw ile
        #     pass
        days = days + 1 if start_date.isoweekday() <= 5 else days
        start_date += delta
    return days


def send_email(msg):
    with app.app_context():
        mail.send(msg)


def create_and_send_admin(name):
    msg = Message('{} dodał swój urlop'.format(name), sender=app.config['MAIL_USERNAME'],
                  recipients=['kuba121201@gmail.com'])
    msg.body = f'''Użytkownik {name} dodał propozycję swojegu urlopu.
    Aby zatwierdzić albo odrzucić kliknij w link http://127.0.0.1:5000{url_for('index')}
    '''
    thr = Thread(target=send_email, args=[msg])
    thr.start()


def accepted_leave_mail(start_date, end_date, receiver, state):
    msg = Message('Twój urlop został {}'.format(state), sender=app.config['MAIL_USERNAME'],
                  recipients=['kuba121201@gmail.com'])
    msg.body = f'''Twój urlop od {start_date.date()} do {end_date.date()} został {state}. 
    Kliknij w link http://127.0.0.1:5000{url_for('index')} aby dowiedzieć się więcej.
    '''
    thr = Thread(target=send_email, args=[msg])
    thr.start()


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
@login_required
def leave(name, opt=None):
    if current_user.role == 'Admin':
        leaves = Leave.query.filter_by(deleted=False).all()
    else:
        leaves = User.query.filter_by(username=current_user.username).first().leave
        leaves = [leave for leave in leaves if leave.deleted == False]

    form_search = SearchForm()
    form = LeaveForm()

    if form_search.validate_on_submit() and form_search.searchText.data:
        leaves = User.query.filter_by(username=form_search.searchText.data).first()
        if leaves is None:
            leaves = Leave.query.filter_by(deleted=False).all()
            flash('Nie ma takiego pracownika', 'danger')
        else:
            flash('{} znaleziony'.format(form_search.searchText.data), 'success')
            leaves = User.query.filter_by(username=form_search.searchText.data.strip()).first().leave
            leaves = [leave for leave in leaves if leave.deleted == False]
        return render_template('leave.html',
                               form=form,
                               leaves=leaves,
                               title=name,
                               form_search=form_search,
                               days_fun=calculate_days)

    if form.start_date.data and form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data
        leave = Leave(start_day=start_date, end_day=end_date, user=current_user)
        db.session.add(leave)
        db.session.commit()
        if current_user.username != 'Admin':
            create_and_send_admin(current_user.username)
        return redirect(url_for('leave', name=current_user.username))

    if opt is not None:
        pass
    return render_template('leave.html',
                           users=User.query.all(),
                           form=form,
                           form_search=form_search,
                           leaves=leaves,
                           title=name,
                           days_fun=calculate_days)


@app.route('/leave-history')
@login_required
def leave_history():
    user = current_user.username
    leaves = User.query.filter_by(username=user).first().leave
    return render_template('leave_history.html', leaves=leaves, days_fun=calculate_days)


@app.route('/leave-history/admin', methods=['POST', 'GET'])
@login_required
def leave_history_admin():
    if current_user.role != 'Admin':
        abort(403)
    form_search = SearchForm()
    if form_search.validate_on_submit() and form_search.searchText.data:
        leaves = User.query.filter_by(username=form_search.searchText.data).first()
        if leaves is None:
            leaves = Leave.query.filter_by(deleted=False).all()
            flash('Nie ma takiego pracownika', 'danger')
        else:
            flash('{} znaleziony'.format(form_search.searchText.data), 'success')
            leaves = User.query.filter_by(username=form_search.searchText.data.strip()).first().leave
            leaves = [leave for leave in leaves if leave.deleted is False]
        return render_template('leave_history_admin.html',
                               leaves=leaves[::-1],
                               form_search=form_search,
                               days_fun=calculate_days)
    leaves = Leave.query.all()
    return render_template('leave_history_admin.html', form_search=form_search, leaves=leaves[::-1], days_fun=calculate_days)


@app.route('/clear')
def clear():
    if current_user.role != 'Admin':
        abort(403)
    Leave.query.delete()
    user = User.query.filter_by(username=current_user.username).first()
    user.days_left = 26
    db.session.commit()
    return redirect(url_for('leave', name=current_user.username))


@app.route('/delete-leave/<int:leave_id>', methods=['GET', 'POST'])
def delete_leave(leave_id):
    if current_user.role != 'Admin':
        abort(403)
    leave_list = Leave.query.filter_by(id=leave_id)
    leave = leave_list.first()
    if leave.accepted == 1:
        leave.user.days_left = leave.user.days_left + calculate_days(leave.start_day, leave.end_day)
    leave.deleted = True
    db.session.commit()
    return redirect(url_for('leave', name=current_user.username))


@app.route('/change-accept/<int:leave_id>/<int:option>')
def change_accept(leave_id, option):
    if current_user.role != 'Admin':
        abort(403)
    leave = Leave.query.filter_by(id=leave_id).first()
    start_date = leave.start_day
    end_date = leave.end_day
    user = User.query.filter_by(username=leave.user.username).first_or_404()
    # accept
    if option == 1:
        if leave.accepted != 1:
            user.days_left = user.days_left - calculate_days(start_date, end_date)
            leave.accepted = 1
            accepted_leave_mail(start_date, end_date, user.email, 'zaakceptowany')

    # waiting
    elif option == 0:
        if leave.accepted == 1:
            user.days_left = user.days_left + calculate_days(start_date, end_date)
        leave.accepted = 0
    # refuse
    elif option == 2:
        if leave.accepted == 1:
            user.days_left = user.days_left + calculate_days(start_date, end_date)
        leave.accepted = 2
        accepted_leave_mail(start_date, end_date, user.email, 'odrzucony')
    else:
        return abort(404)
    db.session.commit()
    return redirect(url_for('leave', name=current_user.username))

@app.route('/recover/<int:leave_id>')
def recover_leave(leave_id):
    leave_status = Leave.query.filter_by(id=leave_id).first().deleted
    Leave.query.filter_by(id=leave_id).first().deleted = True if leave_status is False else False
    db.session.commit()
    return redirect(url_for('leave', name=current_user.username))


@app.errorhandler(404)
def page_not_found(e):
    return e, 404


def to_dict(row):
    if row is None:
        return None
    rtn_dict = dict()
    keys = row.__table__.columns.keys()
    print(type(row))
    for key in keys:
        if key == 'user_id':
            rtn_dict['username'] = User.query.filter_by(id=getattr(row, key)).first().username
        elif key != 'password':
            rtn_dict[key] = getattr(row, key)
    return rtn_dict


@app.route('/excel/download', methods=['GET', 'POST'])
def exportexcel():
    if current_user.role != 'Admin':
        abort(403)
    filename = app.config['UPLOAD_FOLDER'] + "/excel_database.xlsx"
    dataframes = list()
    for i, db_class in enumerate((User.query.all(), Leave.query.all())):
        data = db_class
        data_list = [to_dict(item) for item in data]
        df = pd.DataFrame(data_list)
        dataframes.append(df)
    with pd.ExcelWriter(filename) as writer:
        dataframes[0].to_excel(writer, sheet_name='Dane')
        dataframes[1].to_excel(writer, sheet_name='Urlopy')
        writer.save()
    return send_file(filename, as_attachment=True)
