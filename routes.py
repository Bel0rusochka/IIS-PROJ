from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import *
import hashlib
from sqlalchemy import or_, and_, exists
from PIL import Image as PILImage
import io

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
                return redirect(url_for('index'))
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
                return redirect(url_for('index'))
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
    @app.route('/profile')
    def profiles():
        if session.get('user') is None:
            return redirect(url_for('login'))
        elif session['user'][1] == 'admin' or session['user'][1] == 'moderator':
            users = Users.query.all()
            return '''
            <h1>Profiles</h1>
            <p>Users:</p>
            <ul>''' + ''.join([f'<li><a href="{url_for("profile", login=user.login)}">{user.login}</a></li>' for user in users]) + '''</ul>
            '''
            # return render_template("profiles.html", users=users)
        else:
            return redirect(url_for('profile', login=session['user'][0]))

    @app.route('/shares')
    def shares():
        if session.get('user') is None:
            return redirect(url_for('login'))
        shares = Shares.query.filter_by(recipient_login=session['user'][0]).all()
        return "Shares"

    @app.route('/comrades')
    def comrades():
        if session.get('user') is None:
            return redirect(url_for('login'))
        comrades = Comrades.query.filter_by(user_login=session['user'][0]).all()
        return "Comrades"

    @app.route('/groups')
    def groups():
        if session.get('user') is None:
            return redirect(url_for('login'))
        groups = Groups.query.all()
        return "Groups"


    # @app.route('/delete_profile', methods=['GET', 'POST'])
    # def delete_profile():
    #     if session.get('user') is None:
    #         return redirect(url_for('login'))
    #     if request.method == 'POST':
    #         user = Users.query.get(session['user'][0])
    #         db.session.delete(user)
    #         db.session.commit()
    #         session.pop('user', None)
    #         return redirect(url_for('login'))
    #     return "None"
    #
    @app.route('/settings', methods=['GET', 'POST'])
    def settings():
        if session.get('user') is None:
            return redirect(url_for('login'))
        if request.method == 'POST':
            user = Users.query.get(session['user'][0])
            user.name = request.form['name']
            user.surname = request.form['surname']
            user.mail = request.form['email']
            db.session.commit()
            session['user'] = [user.login, user.role, user.name, user.surname, user.mail]
            return redirect(url_for('profile', login=session['user'][0]))
        return "None"


    @app.route('/logout')
    def logout():
        session.pop('user', None)
        return redirect(url_for('login'))

    @app.route('/image/<int:id>')
    def image(id):
        img = Posts.query.get(id)
        if img:
            return send_file(io.BytesIO(img.image_binary), mimetype='image/jpeg')
        return render_template("image.html")

    @app.route('/')
    def index():
        if session.get('user') is not None:
            user_login = session['user'][0]
            posts = Posts.query.filter(
                or_(
                    Posts.status == "public",
                    and_(
                        Posts.status == "private",
                        Users.comrades.any(
                            and_(
                                Comrades.comrade_login == user_login,
                                Comrades.user_login == Posts.author_login
                            )
                        )
                    ),
                    and_(
                        Posts.status == "private",
                        or_(
                            Posts.author_login == session['user'][0],
                            session['user'][1] == 'admin',
                            session['user'][1] == 'moderator'
                        )
                    )
                )
            )
            return render_template("index.html", posts =posts, user = session['user'], is_logged = True)
        else:
            return render_template("index.html", posts = Posts.query.filter_by(status="public").all(), is_logged = False)


    @app.route('/upload', methods=['POST', 'GET'])
    def upload():
        if session.get('user') is not None:
            if request.method == 'POST':
                text = request.form['text']
                status = 'public'
                image = request.files['image']
                tags = request.form['tags'].split(' ')
                if image:
                    img = PILImage.open(image)
                    img = img.convert('RGB')
                    img.thumbnail((600, 600), PILImage.LANCZOS)

                    img_io = io.BytesIO()
                    img.save(img_io, 'JPEG',quality=100)
                    img_io.seek(0)

                    post = Posts(author_login=session['user'][0], status=status, text=text, image_binary=img_io.read())
                    for tag in tags:
                        if tag == '' or tag == ' ': continue
                        tag_db = Tags.query.get(tag)
                        if tag_db is None:
                            tag_db = Tags(name=tag)
                        post.associated_tags.append(tag_db)
                    db.session.add(post)
                    db.session.commit()
                    return redirect(url_for('index'))
                else:
                    flash("Image is required")
        return redirect(url_for('index'))