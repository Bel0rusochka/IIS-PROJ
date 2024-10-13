from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import *
import hashlib
from sqlalchemy import or_


def registrate_routes(app, db):
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST' and session.get('user') is None:
            login = request.form['login']
            name = request.form['name']
            surname = request.form['surname']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            if password == confirm_password and Users.query.get(login) is None:
                password_db = hashlib.md5(password.encode()).hexdigest()
                user = Users(login=login, name=name, surname=surname, mail=email, password=password_db, role="user")
                session['user'] = [user.login, user.role, user.name, user.surname, user.mail]
                db.session.add(user)
                db.session.commit()
                return redirect(url_for('profile', login=user.login))
            else:
                print("Passwords do not match")
                flash("Passwords do not match")
        elif session.get('user') is not None:
            return redirect(url_for('profile', login=session['user'][0]))
        return render_template("signup.html")

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST' and session.get('user') is None:
            login_email = request.form['login_email']
            password = request.form['password']
            password_db = hashlib.md5(password.encode()).hexdigest()
            user = Users.query.filter(or_(Users.login == login_email, Users.mail == login_email)).first()
            if user is not None and user.password == password_db:
                session['user'] = [user.login, user.role, user.name, user.surname, user.mail]
                return redirect(url_for('profile', login=user.login))
            else:
                flash("Invalid login or password")
        elif session.get('user') is not None:
            return redirect(url_for('profile', login=session['user'][0]))
        return render_template("login.html")

    @app.route('/profile/<login>')
    def profile(login):
        if session.get('user') is None:
            return redirect(url_for('login'))
        if login == session['user'][0] or session['user'][1] == 'admin':
            user = Users.query.get(login)
            return f'''
                    <h1>Profile</h1>
                    <p>Welcome, {user.name} {user.surname}</p>
                    <p>Your login: {user.login}</p>
                    <botton><a href="{url_for('logout')}">Logout</a></botton>
                    '''
        else:
            return redirect(url_for('profile', login=session['user'][0]))


    @app.route('/logout')
    def logout():
        session.pop('user', None)
        return redirect(url_for('login'))

    @app.route('/')
    def index():

        return "Hello, world!"