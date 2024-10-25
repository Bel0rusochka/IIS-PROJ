from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from models import *
import hashlib
from sqlalchemy import or_, and_, exists, not_
from PIL import Image as PILImage
import io


def registrate_routes(app, db):

    def posts_for_user(user_login):
        return Posts.query.filter(
            or_(
                Posts.status == "public",
                # Posts.status == "group",
                and_(
                    Posts.status == "private",
                    Users.viewers.any(
                        and_(
                            Viewers.viewer_login == session['user']['login'],
                            # Viewers.user_login == Posts.author_login
                        )
                    )
                ),
                and_(
                    Posts.status == "private",
                    or_(
                        Posts.author_login == session['user']['login'],
                        # session['user']['role'] == 'admin',
                        # session['user']['role'] == 'moderator'
                    )
                )
            )
        ).order_by(Posts.date.desc())

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST' and session.get('user') is None:
            login = request.form['login']
            name = request.form['name']
            surname = request.form['surname']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            if password == confirm_password and Users.query.get(login) is None and '@' not in login:
                password_db = hashlib.md5(password.encode()).hexdigest()
                user = Users(login=login, name=name, surname=surname, mail=email, password=password_db, role="user")
                session['user'] = {"login": user.login, "role": user.role, "name": user.name, "surname": user.surname, "mail": user.mail}
                db.session.add(user)
                db.session.commit()
                return redirect(url_for('index'))
            else:
                flash("Passwords do not match")
        elif session.get('user') is not None:
            return redirect(url_for('profile', login=session['user']['login'], previos_values={}))
        return render_template("signup.html")

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST' and session.get('user') is None:
            login_email = request.form['login_email']
            password = request.form['password']
            password_db = hashlib.md5(password.encode()).hexdigest()
            user = Users.query.filter(or_(Users.login == login_email, Users.mail == login_email)).first()
            if user is None:
                flash("Invalid login", "error")
            elif user.password != password_db:
                flash("Invalid password", "error")
            else:
                flash("You are logged in", "success")
                session['user'] = {"login": user.login, "role": user.role, "name": user.name, "surname": user.surname, "mail": user.mail}
                return redirect(url_for('index'))
        elif session.get('user') is not None:
            flash("You are already logged in", "error")
            return redirect(url_for('profile', login=session['user']['login']))
        return render_template("login.html")

    @app.route('/profile/<login>')
    def profile(login):
        Users.query.get_or_404(login)
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if login == session['user']['login']:
            user = Users.query.get(login)
            return render_template("profile.html", user=user,is_owner=True,posts = Posts.query.filter(Posts.author_login == login,  Posts.status != 'group').all())
        else:
            active_login = session['user']['login']
            return  render_template("profile.html", user=Users.query.get(login), is_owner=False, posts=posts_for_user(active_login).filter_by(author_login=login).all())

    @app.route('/edit_group/<int:id>', methods=['GET', 'POST'])
    def edit_group(id):
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        group = Groups.query.get_or_404(id)
        users_with_roles = group.users_with_role()

        if  dict(users_with_roles).get(session['user']['login'])  != 'admin':
            flash("You are not an admin of this group", "error")
            return redirect(url_for('group', id=id))

        if request.method == 'POST':
            flash("Group updated", "success")
            group.name = request.form['name']
            group.description = request.form['description']
            db.session.commit()
            return redirect(url_for('group', id=id))
        return render_template("edit_group.html", group=group, users=users_with_roles)

    @app.route('/delete_group', methods=['GET', 'POST'])
    def delete_group():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if request.method == 'POST':
            flash("Group deleted", "success")
            group_id = request.form['group_id']
            group = Groups.query.get(group_id)
            db.session.delete(group)
            db.session.commit()
            return redirect(url_for('groups'))
        return redirect(url_for('index'))

    @app.route('/profile')
    def profiles():
        if session.get('user') is None:
            return redirect(url_for('login'))
        elif session['user']['role'] in ['admin', 'moderator']:
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
        shares_received = Shares.query.filter_by(recipient_login=session['user']['login']).all()
        shares_sent = Shares.query.filter_by(sender_login=session['user']['login']).all()
        return '''
        Shares received: <ul>''' + ''.join([f'<li><a href="{url_for("post", post_id=share.posts_id)}">{share.posts_id}</a></li>' for share in shares_received]) + '''</ul>
        Shares sent: <ul>''' + ''.join([f'<li><a href="{url_for("post", post_id=share.posts_id)}">{share.posts_id}</a></li>' for share in shares_sent]) + '''</ul>
        '''

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
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        groups = Groups.query.all()
        return '''
        <h1>Groups</h1>
        <p>Groups:</p>
        <ul>''' + ''.join([f'<li><a href="{url_for("group", id=group.id)}">{group.name}</a></li>' for group in groups]) + '''</ul>
        '''

    @app.route('/make_admin_group', methods=['GET', 'POST'])
    def make_admin_group():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if request.method == 'POST':
            group_id = request.form['group_id']
            user_login = request.form['user_login']
            flash(f"User {user_login} is an admin now", "success")
            group = Groups.query.get(group_id)
            user = Users.query.get(user_login)
            group.users.append(user)
            db.session.execute(
                GroupsUsers.update().values(
                    role='admin'
                ).where(and_(GroupsUsers.c.user_login == user_login, GroupsUsers.c.group_id == group_id))
            )
            db.session.commit()
            return redirect(url_for('edit_group', id=group_id))
        flash("You are not an admin of this group", "error")
        return redirect(url_for('index'))

    @app.route('/delete_member_group', methods=['GET', 'POST'])
    def delete_member_group():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if request.method == 'POST':
            group_id = request.form['group_id']
            user_login = request.form['user_login']
            flash(f"User {user_login} is removed from the group", "success")
            group = Groups.query.get(group_id)
            user = Users.query.get(user_login)
            user_posts = [post for post in group.posts if post.author_login == user_login]
            for post in user_posts:
               group.posts.remove(post)
            group.users.remove(user)
            db.session.commit()
            return redirect(url_for('edit_group', id=group_id))
        flash("You are not an admin of this group", "error")
        return redirect(url_for('index'))

    @app.route('/groups/<int:id>')
    def group(id):
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        group = Groups.query.get_or_404(id)

        subscribers_dict = group.users_with_role()
        is_admin =  subscribers_dict.get(session['user']['login']) == 'admin'
        return render_template("group.html", group=group, posts = group.posts, is_admin=is_admin, members=subscribers_dict.keys())

    @app.route('/leave_group', methods=['GET', 'POST'])
    def leave_group():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if request.method == 'POST':
            group_id = request.form['group_id']
            group = Groups.query.get(group_id)
            user_posts = [post for post in group.posts if post.author_login == session['user']['login']]
            for post in user_posts:
                group.posts.remove(post)
            user = Users.query.get_or_404((session['user']['login']))
            group.users.remove(user)
            flash("You left the group", "success")
            db.session.commit()
            return redirect(url_for('group', id=group_id))
        return redirect(url_for('index'))

    @app.route('/join_group', methods=['GET', 'POST'])
    def join_group():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if request.method == 'POST':
            group_id = request.form['group_id']
            group = Groups.query.get(group_id)
            user = Users.query.get(session['user']['login'])
            group.users.append(user)
            db.session.commit()
            flash(f"You joined the group {group.name}", "success")
            return redirect(url_for('group', id=group_id))
        return redirect(url_for('index'))

    @app.route('/search', methods=['GET'])
    def search_posts():
        if request.method == 'GET':
            query = request.args.get('query', '').strip()
            sort_by = request.args.get('sort_by', 'relevance')
            tag_list = [tag.strip() for tag in query.split() if tag]
            # if not tag_list:
            #     flash("Please enter valid tags!")
            #     return redirect(url_for('index'))

            if session.get('user') is not None:
                results = posts_for_user(session['user']['login'])
                for tag in tag_list:
                    results = results.filter(Posts.associated_tags.any(Tags.name == tag))
                results = results.all()
            else:
                results = Posts.query.filter_by(status="public").join(Posts.associated_tags)
                for tag in tag_list:
                    results = results.filter(Posts.associated_tags.any(Tags.name == tag))
                results =  results.all()

            if sort_by == 'popularity':
                results = sorted(results, key=lambda post: post.shares_count(), reverse=True)
            elif sort_by == 'date':
                results = sorted(results, key=lambda post: post.date, reverse=True)
            elif sort_by == 'likes':
                results = sorted(results, key=lambda post: post.like_count(), reverse=True)
            elif sort_by == 'comments':
                results = sorted(results, key=lambda post: post.comments_count(), reverse=True)
            return render_template("index.html", posts=results)
        abort(404)

    @app.route('/delete_user', methods=['GET', 'POST'])
    def delete_user():
        if request.method == 'POST':
            user_login = request.form['user_login']
            if session.get('user') is None:
                flash("You are not logged in", "error")
                return redirect(url_for('login'))
            if request.method == 'POST':
                flash("User deleted", "success")
                user = Users.query.get_or_404(user_login)
                db.session.delete(user)
                db.session.commit()
                session.pop('user', None)
                return redirect(url_for('index'))
            abort(404)


    @app.route('/setting/<login>', methods=['GET', 'POST'])
    def setting(login):
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if login != session['user']['login']:
            flash("You are not allowed to edit this profile", "error")
            return redirect(url_for('setting', login=session['user']['login']))
        if request.method == 'POST':

            user = Users.query.get(login)
            user.name = request.form['name']
            user.surname = request.form['surname']
            if request.form['password'] != '':
                if ( request.form['password'] == request.form['confirm_password']):
                    if len(request.form['password']) <= 8:
                        user.password = hashlib.md5(request.form['password'].encode()).hexdigest()
                    else:
                        flash("Password is too short. It should be at least 8 characters", "error")
                else:
                    flash("Passwords do not match", "error")
            db.session.commit()
            flash("Profile updated", "success")
            session['user'] = {"login": user.login, "role": user.role, "name": user.name, "surname": user.surname, "mail": user.mail}
            return redirect(url_for('profile', login=login))
        user = Users.query.get(login)
        return render_template("edit_profile.html", user=user)

    @app.route('/posts/<int:post_id>')
    def post(post_id):
        post = Posts.query.get_or_404(post_id)
        return render_template("post.html", post=post, comments=post.comments.all())

    @app.route('/add_comment/<int:post_id>', methods=['POST'])
    def add_comment(post_id):
        if session.get('user') is None or request.method == 'GET':
            flash("You are not logged in", "error")
            return redirect(url_for('post', post_id=post_id))
        if request.method == 'POST':
            text = request.form['text']
            if text == '':
                flash("Text is required")
                return redirect(url_for('post', post_id=post_id))
            if Posts.query.get(post_id) is None:
                abort(404)
            comment = Comments(author_login=session['user']['login'], text=text, post_id=post_id)
            db.session.add(comment)
            db.session.commit()
            flash("Comment added", "success")
            return redirect(url_for('post', post_id=post_id))

    @app.route('/like', methods=['POST'])
    def like_post():
        if request.method == 'POST':
            post_id = request.form['post_id']

            if session.get('user') is None:
                flash("You are not logged in", "error")
                return redirect(url_for('post', post_id=post_id))
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
        flash("Invalid request", "error")
        return redirect(url_for('index'))

    @app.route('/delete_post>', methods=['POST'])
    def delete_post():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if request.method == 'POST':
            post_id = request.form['post_id']
            post = Posts.query.get(post_id)
            if post.author_login == session['user']['login']:
                db.session.delete(post)
                db.session.commit()
                flash("Post deleted", "success")
            return redirect(url_for('index'))
        return "Delete post"

    @app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
    def edit_post(post_id):
        return "Edit post"

    @app.route('/share_post', methods=['POST'])
    def share_post():
        if request.method == 'POST':
            post_id = request.form['post_id']
            recipient_login = request.form['recipient_login'].strip()

            if session.get('user') is None:
                flash("You are not logged in", "error")
                return redirect(url_for('login'))
            post = Posts.query.get_or_404(post_id)
            if post.status == 'private':
                flash("You can't share a private post", "error")
                return redirect(url_for('post', post_id=post.id))
            sender_login = session.get('user')['login']
            if recipient_login == sender_login:
                flash("You can't share the post with yourself", "error")
                return redirect(url_for('post', post_id=post.id))
            elif not Users.query.get(recipient_login):
                flash("User not found", "error")
                return redirect(url_for('post', post_id=post.id))

            share = Shares(posts_id=post_id, sender_login=sender_login, recipient_login=recipient_login)
            db.session.add(share)
            db.session.commit()

            return redirect(url_for('post', post_id=post.id))
        abort(404)

    @app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
    def edit_comment(comment_id):
        return "Edit comment"

    @app.route('/logout')
    def logout():
        if session.get('user') is not None:
            session.pop('user', None)
            flash("You are logged out", "success")
        return redirect(url_for('login'))

    @app.route('/image/<int:id>')
    def image(id):
        if session.get('user') is None:
            img = Posts.query.filter_by(status="public", id=id).first()
        else:
            img = Posts.query.get(id)
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
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        if session['user']['role'] != 'admin':
            flash("You are not an admin", "error")
            return redirect(url_for('index'))
        return "Admin page"

    def transform_images(image):
        img = PILImage.open(image)
        img = img.convert('RGB')
        img.thumbnail((600, 600), PILImage.LANCZOS)

        img_io = io.BytesIO()
        img.save(img_io, 'JPEG', quality=100)
        img_io.seek(0)
        return img_io.read()

    @app.route('/upload', methods=['POST', 'GET'])
    def upload():
        if session.get('user') is not None:
            if request.method == 'POST':
                text = request.form['text']
                status = request.form['privacy']
                image = request.files['image']
                tags = request.form['tags'].split(' ')

                if image:
                    post = Posts(author_login=session['user']['login'], status=status, text=text, image_binary=transform_images(image))
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
        flash("You are not logged in", "error")
        return redirect(url_for('index'))