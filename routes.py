from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from models import *
import hashlib
from sqlalchemy import or_, and_, exists
from PIL import Image as PILImage
import io

def registrate_routes(app, db):

    def posts_for_user(user_login):
        return Posts.query.filter(
            or_(
                Posts.status == "public",
                and_(
                    Posts.status == "private",
                    Users.viewers.any(
                        and_(
                            Viewers.viewer_login == user_login,
                            Viewers.user_login == Posts.author_login
                        )
                    )
                ),
                and_(
                    Posts.status == "private",
                    or_(
                        Posts.author_login == user_login,
                        session['user']['role'] == 'admin',
                        session['user']['role'] == 'moderator'
                    )
                )
            )
        )
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST' and session.get('user') is None:
            login = request.form['login']
            name = request.form['name']
            surname = request.form['surname']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            if password == confirm_password and Users.query.get(login) is None and '@' in login:
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
            return redirect(url_for('profile', login=session['user']['login']))
        return render_template("signup.html")

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST' and session.get('user') is None:
            login_email = request.form['login_email']
            password = request.form['password']
            password_db = hashlib.md5(password.encode()).hexdigest()
            user = Users.query.filter(or_(Users.login == login_email, Users.mail == login_email)).first()
            if user is not None and user.password == password_db:
                session['user'] = {"login": user.login, "role": user.role, "name":user.name, "surname":user.surname, "mail":user.mail}
                return redirect(url_for('index'))
            else:
                flash("Invalid login or password")
        elif session.get('user') is not None:
            return redirect(url_for('profile', login=session['user']['login']))
        return render_template("login.html")

    @app.route('/profile/<login>')
    def profile(login):
        if session.get('user') is None:
            return redirect(url_for('login'))
        if login == session['user']['login'] or session['user']['role'] == 'admin':
            user = Users.query.get(login)
            return render_template("profile.html", user=user,is_owner=True, posts=user.posts)
        else:
            active_login = session['user']['login']
            return  render_template("profile.html", user=Users.query.get(login), is_owner=False, posts=posts_for_user(active_login).filter_by(author_login=login).all())
    @app.route('/profile')
    def profiles():
        if session.get('user') is None:
            return redirect(url_for('login'))
        elif session['user']['role'] == 'admin' or session['user']['role'] == 'moderator':
            users = Users.query.all()
            return '''
            <h1>Profiles</h1>
            <p>Users:</p>
            <ul>''' + ''.join([f'<li><a href="{url_for("profile", login=user.login)}">{user.login}</a></li>' for user in users]) + '''</ul>
            '''
            # return render_template("profiles.html", users=users)
        else:
            return redirect(url_for('profile', login=session['user']['login']))

    @app.route('/shares')
    def shares():
        if session.get('user') is None:
            return redirect(url_for('login'))
        shares = Shares.query.filter_by(recipient_login=session['user']['login']).all()
        return "Shares"

    @app.route('/users')
    def users():
        if session.get('user') is None:
            return redirect(url_for('login'))
        viewer = Viewers.query.filter_by(user_login=session['user']['login']).all()
        users = Users.query.all()
        return '''
        <h1>Users</h1>
        <p>Viewers:</p>
        <ul>''' + ''.join([f'<li><a href="{url_for("profile", login=user.viewer_login)}">{user.viewer_login}</a></li>' for user in viewer]) + '''</ul>
        <p>Users:</p>
        <ul>''' + ''.join([f'<li><a href="{url_for("profile", login=user.login)}">{user.login}</a></li>' for user in users]) + '''</ul>
        '''

    @app.route('/groups')
    def groups():
        if session.get('user') is None:
            return redirect(url_for('login'))
        groups = Groups.query.all()
        return "Groups"

    @app.route('/search', methods=['GET'])
    def search_posts():
        if request.method == 'GET':
            query = request.args.get('query', '').strip()

            if not query:
                flash("Please enter a valid tag!")
                return redirect(url_for('index'))


            tag_list = [tag.strip() for tag in query.split() if tag]
            if not tag_list:
                flash("Please enter valid tags!")
                return redirect(url_for('index'))

            if session.get('user') is not None:
                results = posts_for_user(session['user']['login'])
                for tag in tag_list:
                    results = results.filter(Posts.associated_tags.any(Tags.name == tag))
                results = results.all()
                return render_template("index.html", posts=results)
            else:
                results = Posts.query.filter_by(status="public").join(Posts.associated_tags)
                for tag in tag_list:
                    results = results.filter(Posts.associated_tags.any(Tags.name == tag))
                results =  results.all()
                return render_template("index.html", posts=results)
        abort(404)

    # @app.route('/delete_profile', methods=['GET', 'POST'])
    # def delete_profile():
    #     if session.get('user') is None:
    #         return redirect(url_for('login'))
    #     if request.method == 'POST':
    #         user = Users.query.get(session['user']['login'])
    #         db.session.delete(user)
    #         db.session.commit()
    #         session.pop('user', None)
    #         return redirect(url_for('login'))
    #     return "None"
    #

    @app.route('/setting', methods=['GET', 'POST'])
    def setting():
        if session.get('user') is None:
            return redirect(url_for('login'))
        if request.method == 'POST':
            user = Users.query.get(session['user']['login'])
            user.name = request.form['name']
            user.surname = request.form['surname']
            if request.form['password'] != '' and request.form['password'] == request.form['confirm_password']:
                user.password = hashlib.md5(request.form['password'].encode()).hexdigest()

            db.session.commit()
            session['user'] = {"login": user.login, "role": user.role, "name": user.name, "surname": user.surname, "mail": user.mail}

            return redirect(url_for('profile', login=session['user']['login']))
        return render_template("edit_profile.html")

    @app.route('/posts/<post_id>', methods=['GET', 'POST'])
    def post(post_id):
        if session.get('user') is None:
            abort(404)
        post = Posts.query.get_or_404(post_id)
        return render_template("post.html", post=post, comments=post.comments.all())

    @app.route('/add_comment/<int:post_id>', methods=['POST'])
    def add_comment(post_id):
        if session.get('user') is None or request.method == 'GET':
            abort(404)
        if request.method == 'POST':
            text = request.form['text']
            if text == '':
                flash("Comment is empty")
                return redirect(url_for('post', post_id=post_id))
            if Posts.query.get(post_id) is None:
                abort(404)
            comment = Comments(author_login=session['user']['login'], text=text, post_id=post_id)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('post', post_id=post_id))

    @app.route('/like/<int:post_id>', methods=['POST'])
    def like_post(post_id):
        if session.get('user') is None:
            abort(404)
        post = Posts.query.get_or_404(post_id)
        user_login = session.get('user')['login']

        if post.likes.filter_by(login=user_login).first():
            post.likes.remove(Users.query.filter_by(login=user_login).first())
            db.session.commit()
        else:
            user = Users.query.filter_by(login=user_login).first()
            post.likes.append(user)
            db.session.commit()

        return redirect(url_for('post', post_id=post.id))
    @app.route('/logout')
    def logout():
        session.pop('user', None)
        return redirect(url_for('login'))

    @app.route('/image/<int:id>')
    def image(id):
        if session.get('user') is None:
            img = Posts.query.filter_by(status="public", id=id).first()
        else:
            img = posts_for_user(session['user']['login']).filter_by(id=id).first()
        if img:
            return send_file(io.BytesIO(img.image_binary), mimetype='image/jpeg')
        abort(404)

    @app.route('/')
    def index():
        if session.get('user') is not None:
            return render_template("index.html", posts = posts_for_user(session['user']['login']))
        else:
            return render_template("index.html", posts = Posts.query.filter_by(status="public").all())

    @app.route('/admin')
    def admin():
        if session.get('user') is None:
            return redirect(url_for('login'))
        if session['user']['role'] != 'admin':
            return redirect(url_for('index'))
        return "Admin page"
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

                    post = Posts(author_login=session['user']['login'], status=status, text=text, image_binary=img_io.read())
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