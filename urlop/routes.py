from flask import render_template, redirect, url_for, request, flash, abort
from flask_login import login_user, current_user, logout_user, login_required
from urlop import app, db, bcrypt
from urlop.models import User, Leave
from urlop.forms import LoginForm, RegisterForm, LeaveForm, SearchForm
from flask_bcrypt import Bcrypt
from datetime import date


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

    user = User.query.filter_by(username=name).first_or_404()
    if current_user.role == 'Admin':
        leaves = Leave.query.all()
    else:
        leaves = User.query.filter_by(username=current_user.username).first().leave

    if form_search.validate_on_submit():
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
        user.days_left -= abs(start_date - end_date).days
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
    leave.user.days_left += abs(leave.start_day - leave.end_day).days
    leave_list.delete()
    db.session.commit()
    return redirect(url_for('leave', name=current_user.username))


@app.route('/change-accept/<int:leave_id>')
def change_accept(leave_id):
    leave = Leave.query.filter_by(id=leave_id).first()
    leave.accepted = not leave.accepted
    db.session.commit()
    return redirect(url_for('leave', name=current_user.username))


# @app.route("/search/<string:text>", methods=["POST", "GET"])
# def search(text):
#     if text.strip() == "":
#         return redirect(url_for('leave', name=current_user.username))
#     else:
#         return render_template('leave.html',
#                                 form=form,
#                                 leaves=User.query.filter_by(username=text.strip()).leave,
#                                 title=current_user.username)
    # cursor = mysql.connection.cursor()
    # query = "select word_eng from words where word_eng LIKE '{}%' order by word_eng".format(searchbox)#This is just example query , you should replace field names with yours
    # cursor.execute(query)
    # result = cursor.fetchall()
    # return jsonify(result)


@app.errorhandler(404)
def page_not_found(e):
    return e, 404
