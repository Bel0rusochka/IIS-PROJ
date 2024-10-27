from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from models import *
import hashlib
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
            role = 'user'
            request_data = {'login': login, 'name': name, 'surname': surname, 'email': email, 'password': password, 'confirm_password': confirm_password}
            if password != confirm_password:
                flash("Passwords do not match", "error")
                request_data.pop('password')
                request_data.pop('confirm_password')
            elif Users.get_user(login) is not None:
                flash("User already exists with this login", "error")
                request_data.pop('login')
            elif '@' in login:
                flash("Login cannot contain '@'", "error")
                request_data.pop('login')
            elif Users.get_user(email) is not None:
                flash("User already exists with this email", "error")
                request_data.pop('email')
            elif len(password) < 8:
                flash("Password is too short. It should be at least 8 characters", "error")
                request_data.pop('password')
                request_data.pop('confirm_password')
            else:
                session['user'] = {"login":login, "role": role, "name": email, "surname": surname, "mail": name}

                password_db = hashlib.md5(password.encode()).hexdigest()
                Users.add_user(login, email, password_db, name, surname,role)
                return redirect(url_for('index'))
            return render_template("signup.html", previos_values=request_data)

        elif session.get('user') is not None:
            return redirect(url_for('profile', login=session['user']['login'], previos_values={}))
        return render_template("signup.html")

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST' and session.get('user') is None:
            login_email = request.form['login_email']
            password = request.form['password']
            request_data = {'login_email': login_email}
            password_db = hashlib.md5(password.encode()).hexdigest()
            user = Users.get_user(login_email)

            if user is None:
                flash("Invalid login", "error")
                request_data.pop('login_email')
            elif user.password != password_db:
                flash("Invalid password", "error")
            else:
                flash("You are logged in", "success")
                session['user'] = {"login": user.login, "role": user.role, "name": user.name, "surname": user.surname, "mail": user.mail}
                return redirect(url_for('index'))
            return render_template("login.html", previos_values=request_data)
        elif session.get('user') is not None:
            flash("You are already logged in", "error")
            return redirect(url_for('profile', login=session['user']['login']))
        return render_template("login.html")

    @app.route('/profile/<login>')
    def profile(login):
        user = Users.get_user_or_404(login)
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        elif request.method == 'GET' and login == session['user']['login']:
            post_type = request.args.get('posts_type', 'not_group')
            posts = user.get_user_posts_by_privacy(post_type)
            return render_template("profile.html", user=user, posts=posts)
        else:
            active_user = Users.get_user_or_404(session['user']['login'])
            posts = active_user.get_profile_posts(login)
            return  render_template("profile.html", user=user, posts=posts)

    @app.route('/subscribe', methods=['GET', 'POST'])
    def subscribe():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        if request.method == 'POST':
            user_login = request.form['user_login']
            user = Users.get_user_or_404(user_login)
            friend_login = session['user']['login']

            if user is None:
                flash("User not found", "error")
            elif user_login == friend_login:
                flash("You can't subscribe to yourself", "error")
            elif friend_login in user.get_friends_login_list():
                flash("You are already friends", "error")
            else:
                user.add_friend(friend_login)
                flash("You are now friends", "success")
            return redirect(url_for('profile', login=user_login))
        return redirect(url_for('index'))

    @app.route('/unsubscribe', methods=['GET', 'POST'])
    def unsubscribe():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        if request.method == 'POST':
            user_login = request.form['user_login']
            user = Users.get_user_or_404(user_login)
            friend_login = session['user']['login']

            if user is None:
                flash("User not found", "error")
            elif user_login == friend_login:
                flash("You can't unsubscribe from yourself", "error")
            elif friend_login not in user.get_friends_login_list():
                flash("You are not friends", "error")
            else:
                user.delete_friend(friend_login)
                flash("You are not friends anymore", "success")
            return redirect(url_for('profile', login=user_login))
        return redirect(url_for('index'))

    @app.route('/edit_group/<int:id>', methods=['GET', 'POST'])
    def edit_group(id):
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        group = Groups.get_group_or_404(id)
        users_with_roles = group.get_users_with_role()

        if  users_with_roles.get(session['user']['login'])  != 'admin':
            flash("You are not an admin of this group", "error")
            return redirect(url_for('group', id=id))

        if request.method == 'POST':
            flash("Group updated", "success")
            group.edit_group( request.form['name'], request.form['description'])
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
            group.delete_group()
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

    @app.route('/users', methods=['GET', 'POST'])
    def users():
        if session.get('user') is None:
            return redirect(url_for('login'))

        friend = Friends.query.filter_by(user_login=session['user']['login']).all()
        users = Users.query.all()

        show_my_viewers = False
        show_all_users = True
        show_add_viewer_popup = False

        if request.method == 'POST':
            if 'show_my_viewers' in request.form:
                show_my_viewers = True
                show_all_users = False
            elif 'show_all_users' in request.form:
                show_my_viewers = False
                show_all_users = True
            elif 'add_viewer' in request.form:
                show_add_viewer_popup = True

        return render_template('users.html',
                               friend=friend,
                               users=users,
                               show_my_viewers=show_my_viewers,
                               show_all_users=show_all_users,
                               show_add_viewer_popup=show_add_viewer_popup)

    @app.route('/groups')
    def groups():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        groups = Groups.query.all()
        return render_template('groups.html', groups=groups)

    @app.route('/make_admin_group', methods=['GET', 'POST'])
    def make_admin_group():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        if request.method == 'POST':
            group_id = request.form['group_id']
            user_login = request.form['user_login']

            flash(f"User {user_login} is an admin now", "success")
            group = Groups.get_group_or_404(group_id)
            group.make_admin(user_login)
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

            user = Users.query.get_or_404(user_login)
            group = Groups.query.get_or_404(group_id)
            group.delete_member_group(user)
            return redirect(url_for('edit_group', id=group_id))
        flash("You are not an admin of this group", "error")
        return redirect(url_for('index'))

    @app.route('/groups/<int:id>')
    def group(id):
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        group = Groups.get_group_or_404(id)
        subscribers_dict = group.get_users_with_role()

        is_admin =  subscribers_dict.get(session['user']['login']) == 'admin'
        return render_template("group.html", group=group, posts = group.posts, is_admin=is_admin, members=subscribers_dict.keys())

    @app.route('/leave_group', methods=['GET', 'POST'])
    def leave_group():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        if request.method == 'POST':
            group_id = request.form['group_id']
            group = Groups.get_group_or_404(group_id)
            user = Users.get_user_or_404(session['user']['login'])
            group.delete_member_group(user)

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
            group = Groups.get_group_or_404(group_id)
            user = Users.get_user_or_404(session['user']['login'])
            group.add_member_group(user)

            flash(f"You joined the group {group.name}", "success")
            return redirect(url_for('group', id=group_id))
        return redirect(url_for('index'))

    @app.route('/search', methods=['GET'])
    def search_posts():
        if request.method == 'GET':
            query = request.args.get('query', '').strip().replace(' ', '#')
            sort_by = request.args.get('sort_by', 'relevance')
            tag_list = [tag.strip() for tag in query.split("#") if tag]

            if session.get('user') is not None:
                user = Users.get_user_or_404(session['user']['login'])
                results = user.get_posts_for_user_feed()
                for tag in tag_list:
                    results = results.filter(Posts.associated_tags.any(Tags.name == tag))
                results = results.all()
            else:
                results = Posts.get_all_posts_by_privacy('public')
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
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        if request.method == 'POST':
            user_login = request.form['user_login']
            Users.delete_user(user_login)
            session.pop('user', None)
            flash("User deleted", "success")
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
            user.change_user_data(name=request.form['name'], surname=request.form['surname'])
            session['user'] = {"login": user.login, "role": user.role, "name": user.name, "surname": user.surname,
                               "mail": user.mail}

            if request.form['password'] != '':
                if ( request.form['password'] == request.form['confirm_password']):
                    if len(request.form['password']) >= 8:
                        user.change_user_data(password=hashlib.md5(request.form['password'].encode()).hexdigest())
                    else:
                        flash("Password is too short. It should be at least 8 characters", "error")
                        return redirect(url_for('setting', login=login))
                else:
                    flash("Passwords do not match", "error")
                    return redirect(url_for('setting', login=login))

            flash("Profile updated", "success")
            return redirect(url_for('profile', login=login))
        user = Users.query.get(login)
        return render_template("edit_profile.html", user=user)

    @app.route('/posts/<int:post_id>')
    def post(post_id):
        if session.get('user') is None:
            post = Posts.query.filter_by(status="public", id=post_id).first()
        else:
            user = Users.query.get(session['user']['login'])
            post = user.get_posts_for_user().filter_by(id=post_id).first()
        if post is None:
            abort(404)
        return render_template("post.html", post=post, comments=post.comments.all())

    @app.route('/add_comment/<int:post_id>', methods=['POST'])
    def add_comment(post_id):
        if session.get('user') is None or request.method == 'GET':
            flash("You are not logged in", "error")
            return redirect(url_for('post', post_id=post_id))

        if request.method == 'POST':
            text = request.form['text']

            post = Posts.get_post_or_404(post_id)
            post.add_comment(text, session['user']['login'])
            flash("Comment added", "success")
            return redirect(url_for('post', post_id=post_id))

    @app.route('/delete_comment', methods=['GET', 'POST'])
    def delete_comment():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        comment = Comments.get_comment_or_404(request.form['comment_id'])

        if request.method == 'POST' and  comment.author_login == session['user']['login']:
            comment.delete_comment()
            flash("Comment deleted", "success")
            return redirect(url_for('post', post_id=comment.post_id))
        return "Edit comment"

    @app.route('/like', methods=['POST'])
    def like_post():
        if request.method == 'POST':
            post_id = request.form['post_id']

            if session.get('user') is None:
                flash("You are not logged in", "error")
                return redirect(url_for('post', post_id=post_id))

            post = Posts.get_post_or_404(post_id)
            user_login = session.get('user')['login']
            post.like_post(user_login)

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
            post = Posts.get_post_or_404(post_id)
            if post.author_login == session['user']['login']:
                post.delete_post()
                flash("Post deleted", "success")
            return redirect(url_for('index'))
        return "Delete post"

    @app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
    def edit_post(post_id):
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        if request.method == 'POST':
            tags_input = request.form['tags'].strip()
            tags = list(filter(None, tags_input.split('#')))

            hash_count = tags_input.count('#')
            if hash_count != (len(tags)) and not request.form['tags'].startswith('#'):
                flash("Tags should start with # and be separated by #", "error")
            elif hash_count != (len(tags)):
                flash("Tags should be separated by #", "error")
            else:
                post = Posts.get_post_or_404(post_id)
                text = request.form['text']
                status = request.form['privacy']
                associated_tags = []

                for tag in tags:
                    if tag == '' or tag == ' ': continue
                    tag_db = Tags.query.get(tag)
                    if tag_db is None:
                        tag_db = Tags(name=tag)
                    associated_tags.append(tag_db)
                post.edit_post(text, status, associated_tags)
                flash("Post updated", "success")
                return redirect(url_for('post', post_id=post.id))
        return render_template("edit_post.html", post = Posts.get_post_or_404(post_id))

    @app.route('/share_post', methods=['POST'])
    def share_post():
        if request.method == 'POST':
            post_id = request.form['post_id']
            recipient_login = request.form['recipient_login'].strip()

            if session.get('user') is None:
                flash("You are not logged in", "error")
                return redirect(url_for('login'))

            post = Posts.get_post_or_404(post_id)
            sender_login = session.get('user')['login']

            if recipient_login == sender_login:
                flash("You can't share the post with yourself", "error")
                return redirect(url_for('post', post_id=post.id))
            elif not Users.query.get(recipient_login):
                flash("User not found", "error")
                return redirect(url_for('post', post_id=post.id))

            if post.status == 'private':
                author = post.author

                if recipient_login in author.get_friends_login_list() or recipient_login == author.login:
                    post.share_post(sender_login, recipient_login)
                    flash("Post shared", "success")
                    return redirect(url_for('post', post_id=post.id))
                else:
                    flash("You can't share this post with this user", "error")
                return redirect(url_for('post', post_id=post.id))
            else:

                flash("Post shared", "success")
                share = Shares(posts_id=post_id, sender_login=sender_login, recipient_login=recipient_login)
                db.session.add(share)
                db.session.commit()

            return redirect(url_for('post', post_id=post.id))
        abort(404)

    @app.route('/logout')
    def logout():
        if session.get('user') is not None:
            session.pop('user', None)
            flash("You are logged out", "success")
        return redirect(url_for('login'))

    @app.route('/image/<int:id>')
    def image(id):
        if session.get('user') is None:
            img = Posts.get_all_posts_by_privacy('public').filter_by(id=id).first()
        else:
            img = Posts.get_post_or_404(id)
        if img:
            return send_file(io.BytesIO(img.image_binary), mimetype='image/jpeg')
        abort(404)

    @app.route('/')
    def index():
        if session.get('user') is not None:
            user = Users.get_user_or_404(session['user']['login'])
            return render_template("index.html", posts = user.get_posts_for_user_feed())
        else:
            return render_template("index.html", posts = Posts.get_all_posts_by_privacy('public'))

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

                tags = request.form['tags'].strip()
                tags = list(filter(None, tags.split('#')))
                hash_count = request.form['tags'].count('#')
                if hash_count != (len(tags)) and not request.form['tags'].startswith('#'):
                    flash("Tags should start with # and be separated by #", "error")
                elif hash_count != (len(tags)):
                    flash("Tags should be separated by #", "error")
                else:
                    Posts.create_post(session['user']['login'], status, text, transform_images(image),tags)
                    return redirect(url_for('index'))

        flash("You are not logged in", "error")
        return redirect(url_for('index'))