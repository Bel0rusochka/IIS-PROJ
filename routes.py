from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from urllib.parse import urlencode
from models import *
import hashlib
from PIL import Image as PILImage
import io


def registrate_routes(app, db):

    def add_previous_page():
        if request.url == request.host_url:
            session['previous_pages'] = []
        if len(session['previous_pages']) == 0:
            session['previous_pages'].append(request.url)
            session.modified = True
        elif request.url != session['previous_pages'][-1]:
            session['previous_pages'].append(request.url)
            session.modified = True

    @app.before_request
    def before_request():
        if session.get('previous_pages') is None:
            session['previous_pages'] = []

    @app.route('/go_back')
    def go_back():
        if len(session['previous_pages']) > 0 and session['previous_pages'][-1] != request.referrer:
            return redirect(session['previous_pages'].pop())
        elif session['previous_pages'][-1] == request.referrer:
            session['previous_pages'].pop()
            session.modified = True
            return redirect( session['previous_pages'].pop())
        return redirect(url_for('index'))

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST' and session.get('user') is None:
            login = request.form['login'].strip()
            name = request.form['name'].strip()
            surname = request.form['surname'].strip()
            email = request.form['email'].strip()
            password = request.form['password'].strip()
            confirm_password = request.form['confirm_password'].strip()
            role = 'user'
            request_data = {'login': login, 'name': name, 'surname': surname, 'email': email, 'password': password, 'confirm_password': confirm_password}
            bad_data = False

            if password != confirm_password:
                flash("Confirm password does not match", "error")
                request_data.pop('password')
                request_data.pop('confirm_password')
                bad_data = True
            elif len(password) < 8:
                flash("Password is too short. It should be at least 8 characters", "error")
                request_data.pop('password')
                request_data.pop('confirm_password')
                bad_data = True

            if Users.get_user(login) is not None:
                flash("User already exists with this login", "error")
                request_data.pop('login')
                bad_data = True
            elif '@' in login or " " in login:
                flash("Login is invalid", "error")
                request_data.pop('login')
                bad_data = True
            elif login == "":
                flash("Login is empty", "error")
                request_data.pop('login')
                bad_data = True
            elif len(login) > 60:
                flash("Login is too long", "error")
                request_data.pop('login')
                bad_data = True

            if Users.get_user(email) is not None:
                flash("User already exists with this email", "error")
                request_data.pop('email')
                bad_data = True
            elif email == "":
                flash("Email is empty", "error")
                request_data.pop('name')
                bad_data = True
            elif len(email) > 60:
                flash("Email is too long", "error")
                request_data.pop('email')
                bad_data = True
            elif " " in email:
                flash("Email is invalid", "error")
                request_data.pop('email')
                bad_data = True

            if len(name) > 60:
                flash("Name is too long", "error")
                request_data.pop('name')
                bad_data = True
            elif " " in name or "@" in name:
                flash("Name is invalid", "error")
                request_data.pop('name')
                bad_data = True

            if len(surname) > 60:
                flash("Surname is too long", "error")
                request_data.pop('surname')
                bad_data = True
            elif " " in surname or "@" in surname:
                flash("Surname is invalid", "error")
                request_data.pop('surname')
                bad_data = True

            if not bad_data:
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
            add_previous_page()
            post_type = request.args.get('posts_type', 'not_group')
            posts = user.get_user_posts_by_privacy(post_type)
            return render_template("profile.html", user=user, posts=posts)
        else:
            add_previous_page()
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
            follower_login = session['user']['login']

            if user is None:
                flash("User not found", "error")
            elif user_login == follower_login:
                flash("You can't subscribe to yourself", "error")
            elif follower_login in user.get_followers_login_list():
                flash("You are already followers", "error")
            else:
                user.add_follower(follower_login)
                flash("You are now followers", "success")
            return redirect(request.referrer or url_for('index'))
        return redirect(url_for('index'))

    @app.route('/unsubscribe', methods=['GET', 'POST'])
    def unsubscribe():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        if request.method == 'POST':
            user_login = request.form['user_login']
            user = Users.get_user_or_404(user_login)
            follower_login = session['user']['login']

            if user is None:
                flash("User not found", "error")
            elif user_login == follower_login:
                flash("You can't unsubscribe from yourself", "error")
            elif follower_login not in user.get_followers_login_list():
                flash("You are not followers", "error")
            else:
                user.delete_follower(follower_login)
                flash("You are not followers anymore", "success")
            return redirect(request.referrer or url_for('index'))
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
            group_name = request.form['name'].strip()
            group_description = request.form['description'].strip()

            if group_name == '':
                flash("Group name is empty", "error")
            elif "@" in group_name:
                flash("Group name is invalid", "error")
            elif len(group_name) > 60:
                flash("Group name is too long", "error")
            elif group_name != group.name:
                flash("Group name updated", "success")
                group.edit_group( request.form['name'], group.description)


            if len(group_description) > 60:
                flash("Group description is too long", "error")
            elif group_description != group.description:
                flash("Group description updated", "success")
                group.edit_group(group.name, request.form['description'])


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

        add_previous_page()

        shares_received = Shares.query.filter_by(recipient_login=session['user']['login']).all()
        shares_sent = Shares.query.filter_by(sender_login=session['user']['login']).all()
        return render_template('shares.html', shares=shares_received)

    @app.route('/shares/sent')
    def shares_sent():
        if session.get('user') is None:
            return redirect(url_for('login'))

        add_previous_page()
        shares = Shares.query.filter_by(sender_login=session['user']['login']).all()
        return render_template('shares.html', shares=shares)

    @app.route('/users')
    def users():
        if session.get('user') is None:
            return redirect(url_for('login'))
        add_previous_page()
        users = Users.query.all()
        return render_template('users.html', users=users)

    @app.route('/users/followers')
    def followers():
        if session.get('user') is None:
            return redirect(url_for('login'))
        add_previous_page()
        user = Users.get_user_or_404(session['user']['login'])
        return render_template('users.html', users=user.get_followers_list())

    @app.route('/users/following')
    def following():
        if session.get('user') is None:
            return redirect(url_for('login'))
        add_previous_page()
        user = Users.get_user_or_404(session['user']['login'])
        return render_template('users.html', users=user.get_following_list())


    @app.route('/groups', methods=['GET', 'POST'])
    def groups():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        add_previous_page()
        groups = Groups.query.all()
        return render_template('groups.html',groups=groups)

    @app.route('/create_group', methods=['GET', 'POST'])
    def create_group():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))

        if request.method == 'POST':
            group_name = request.form['group-name'].strip()
            group_description = request.form['group-description'].strip()
            bad_data = False

            if group_name == '':
                flash("Group name is empty", "error")
                bad_data = True
            elif "@" in group_name:
                flash("Group name is invalid", "error")
                bad_data = True
            elif len(group_name) > 60:
                flash("Group name is too long", "error")
                bad_data = True

            if len(group_description) > 60:
                flash("Group description is too long", "error")
                bad_data = True

            if not bad_data:
                user = Users.get_user_or_404(session['user']['login'])
                group = Groups.create_group(group_name, group_description, user)
                flash("Group created", "success")
                return redirect(url_for('group', id=group.id))
        return redirect(url_for('groups'))

    @app.route('/groups/following_groups', methods=['GET', 'POST'])
    def following_groups():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        add_previous_page()
        user = Users.get_user_or_404(session['user']['login'])
        return render_template('groups.html',groups=user.groups )

    @app.route('/managed_groups', methods=['GET', 'POST'])
    def managed_groups():
        if session.get('user') is None:
            flash("You are not logged in", "error")
            return redirect(url_for('login'))
        add_previous_page()
        user = Users.get_user_or_404(session['user']['login'])
        return render_template('groups.html',groups=user.managed_groups())

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
            return redirect(request.referrer or url_for('index'))
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
            return redirect(request.referrer or url_for('index'))
        return redirect(url_for('index'))

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
            user_name = request.form['name'].strip()
            user_surname = request.form['surname'].strip()
            # user.change_user_data(name=request.form['name'], surname=request.form['surname'])

            if "@" in user_name or " " in user_name or len(user_name) > 60:
                flash("Name is invalid", "error")
            elif user_name != user.name:
                flash("Name updated", "success")
                user.change_user_data(name=user_name)

            if "@" in user_surname or " " in user_surname or len(user_surname) > 60:
                flash("Surname is invalid", "error")
            elif user_surname != user.surname:
                flash("Surname updated", "success")
                user.change_user_data(surname=user_surname)

            if request.form['password'] != '':
                if ( request.form['password'] == request.form['confirm_password']):
                    if len(request.form['password']) >= 8:
                        flash("Password updated", "success")
                        user.change_user_data(password=hashlib.md5(request.form['password'].encode()).hexdigest())
                    else:
                        flash("Password is too short. It should be at least 8 characters", "error")
                        return redirect(url_for('setting', login=login))
                else:
                    flash("Passwords do not match", "error")
                    return redirect(url_for('setting', login=login))

            session['user'] = {"login": user.login, "role": user.role, "name": user.name, "surname": user.surname,
                               "mail": user.mail}
            return redirect(url_for('setting', login=login))
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
        add_previous_page()
        return render_template("post.html", post=post, comments=post.comments.all())

    @app.route('/go_to_index')
    def go_to_index():
        query_params = session.get('index_params', {})
        if query_params:
            return redirect(url_for('index') + '?' + urlencode(query_params))
        else:
            return redirect(url_for('index'))

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

                if recipient_login in author.get_followers_login_list() or recipient_login == author.login:
                    post.share_post(sender_login, recipient_login)
                    flash("Post shared", "success")
                    return redirect(url_for('post', post_id=post.id))
                else:
                    flash("You can't share this post with this user", "error")
                return redirect(url_for('post', post_id=post.id))
            else:

                flash("Post shared", "success")
                post.share_post(sender_login, recipient_login)

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
        add_previous_page()
        if request.method == 'GET':
            session['index_params'] = request.args.to_dict()
            query = request.args.get('query', '').strip().replace(' ', '#')

            sort_by = request.args.get('sort_by', 'relevance')
            filter_by = request.args.get('filter', 'all')
            tag_list = [tag.strip() for tag in query.split("#") if tag]

            if session.get('user') is not None:
                user = Users.get_user_or_404(session['user']['login'])
                results = user.get_posts_for_user_feed()

                for tag in tag_list:
                    results = results.filter(Posts.associated_tags.any(Tags.name == tag))
                results = results.all()
                print(filter_by)
                if filter_by == 'all':
                    results = results
                elif filter_by == 'followers':
                    print(user.get_followers_login_list())
                    results = [post for post in results if
                               post.author_login in user.get_followers_login_list() and post.author_login != user.login]
                elif filter_by == 'following':

                    results = [post for post in results if
                               post.author_login in user.get_following_login_list() and post.author_login != user.login]
            else:
                results = Posts.get_all_posts_by_privacy('public')
                for tag in tag_list:
                    results = results.filter(Posts.associated_tags.any(Tags.name == tag))
                results = results.all()

            if sort_by == 'shares':
                results = sorted(results, key=lambda post: post.shares_count(), reverse=True)
            elif sort_by == 'date':
                results = sorted(results, key=lambda post: post.date, reverse=True)
            elif sort_by == 'likes':
                results = sorted(results, key=lambda post: post.like_count(), reverse=True)
            elif sort_by == 'comments':
                results = sorted(results, key=lambda post: post.comments_count(), reverse=True)



            return render_template("index.html", posts=results)
        else:
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
                text = request.form['text'].strip()
                status = request.form['privacy']
                image = request.files['image']
                tags = request.form['tags'].strip()
                tags = list(filter(None, tags.split('#')))
                hash_count = request.form['tags'].count('#')
                bad_data = False

                if hash_count != (len(tags)) and not request.form['tags'].startswith('#'):
                    flash("Tags should start with # and be separated by #", "error")
                    bad_data = True
                elif hash_count != (len(tags)):
                    flash("Tags should be separated by #", "error")
                    bad_data = True

                if len(text) > 1000:
                    flash("Text is too long", "error")
                    bad_data = True

                if not bad_data:
                    flash("Post created", "success")
                    Posts.create_post(session['user']['login'], status, text, transform_images(image),tags)
                    return redirect(url_for('index'))
        return redirect(url_for('index'))