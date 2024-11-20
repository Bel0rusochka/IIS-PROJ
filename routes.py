from flask import render_template, request, redirect, url_for, flash, session, send_file, abort
from models import *
import hashlib
from PIL import Image as PILImage
import io
from functools import wraps
import re


def registrate_routes(app, db):

    #This function is used to validate the login, name, surname of the user and the group name
    def validate_name(login, min_size=2):
        pattern = r'^[a-zA-Z0-9]{' + str(min_size) + r',60}$'
        return re.match(pattern, login) is not None

    #This function is used to transform the image to the format that can be saved in the database
    def transform_images(image):
        img = PILImage.open(image)
        img = img.convert('RGB')
        img.thumbnail((600, 600), PILImage.LANCZOS)

        img_io = io.BytesIO()
        img.save(img_io, 'JPEG', quality=100)
        img_io.seek(0)
        return img_io.read()

    #This function is used to check if the user exists in database
    def user_exists(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if  session.get('user') is not None:
                user = Users.get_user(session['user'])
                if user is None:
                    session.pop('user', None)
                    flash("User not found", "error")
                    return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    #This wrapper is used to check if the user is logged in
    def require_login(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('user') is None:
                flash("You are not logged in", "error")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    
    #This wrapper is used to check if the user is banned
    def require_not_banned(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('user') is not None:
                active_user = Users.get_user_or_404(session['user'])
                if active_user.is_banned:
                    flash("You are banned", "error")
                    return redirect(url_for('banned'))
            return f(*args, **kwargs)
        return decorated_function
    
    #This wrapper is used to check if the user is an admin or a moderator
    def require_admin_or_moder(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            active_user = Users.get_user_or_404(session['user'])
            if active_user.role != 'admin' and active_user.role != 'moderator':
                flash("You are not an admin or moderator", "error")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        
        return decorated_function

    #This function is used to save the previous page in the session
    def add_previous_page():
        if request.url == request.host_url:
            session['previous_pages'] = []

        if len(session['previous_pages']) == 0:
            session['previous_pages'].append(request.url)
            session.modified = True
        elif request.url != session['previous_pages'][-1]:
            session['previous_pages'].append(request.url)
            session.modified = True

    #This function is used to initialize the previous_pages variables in session
    @app.before_request
    def before_request():
        session.permanent = True
        if session.get('previous_pages') is None:
            session['previous_pages'] = []

    #This function is used to redirect the user to the previous page
    @app.route('/go_back')
    @user_exists
    def go_back():
        if len(session['previous_pages']) > 0 and session['previous_pages'][-1] != request.referrer:
            return redirect(session['previous_pages'].pop())
        elif session['previous_pages'][-1] == request.referrer:
            session['previous_pages'].pop()
            session.modified = True
            return redirect( session['previous_pages'].pop())
        return redirect(url_for('index'))

    #This function is used to register a new user in the database
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if session.get('user') is not None:
            flash("You are already logged in", "error")
            return redirect(url_for('profile', login=session['user']))

        if request.method == 'POST':
            login = request.form['login'].strip()
            name = request.form['name'].strip()
            surname = request.form['surname'].strip()
            email = request.form['email'].strip()
            password = request.form['password'].strip()
            confirm_password = request.form['confirm_password'].strip()
            role = 'user'

            request_data = {'login': login, 'name': name, 'surname': surname, 'email': email, 'password': password, 'confirm_password': confirm_password} #
            bad_data = False

            #Validation of the user data
            if password != confirm_password or len(password) < 8:
                flash("Passwords do not match or are less than 8 characters", "error")
                request_data.pop('password')
                request_data.pop('confirm_password')
                bad_data = True

            if not validate_name(login) or Users.get_user(login) is not None:
                flash("Login is invalid", "error")
                request_data.pop('login')
                bad_data = True

            if Users.get_user(email) is not None or email == "" or len(email) > 60 or " " in email:
                flash("Email is invalid", "error")
                request_data.pop('email')
                bad_data = True

            if not validate_name(name,min_size=0):
                flash("Name is invalid", "error")
                request_data.pop('name')
                bad_data = True

            if not validate_name(surname,min_size=0):
                flash("Surname is invalid", "error")
                request_data.pop('surname')
                bad_data = True

            if not bad_data:
                session['user'] = login #Saving the user in the session
                password_db = hashlib.md5(password.encode()).hexdigest() #Hashing the password
                Users.add_user(login, email, password_db, name, surname,role)
                return redirect(url_for('index'))
            return render_template("signup.html", previous_values=request_data) #Returning the signup page with the previous values, if some of the data is invalid
        return render_template("signup.html")

    #This function is used to login the user
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if session.get('user') is not None:
            flash("You are already logged in", "error")
            return redirect(url_for('profile', login=session['user']))

        if request.method == 'POST':
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
                session['user'] = user.login
                flash("You are logged in", "success")
                return redirect(url_for('index'))
            return render_template("login.html", previous_values=request_data)
        return render_template("login.html")

    #This function is used to display the profile of the user
    @app.route('/profile/<login>')
    @user_exists
    @require_login
    @require_not_banned
    def profile(login):
        user = Users.get_user_or_404(login)
        active_user = Users.get_user_or_404(session['user'])

        if request.method == 'GET' and login == active_user.login:
            #Implementing the selection of the posts type. The user can select the show all his posts or only the posts that are bound to the groups
            add_previous_page()
            post_type = request.args.get('posts_type', 'not_group')
            posts = user.get_user_posts_by_privacy(post_type)
            return render_template("profile.html", user=user, posts=posts)
        else:
            add_previous_page()
            posts = active_user.get_profile_posts(login)
            is_following = active_user in user.get_followers_list()
            return  render_template("profile.html", user=user, posts=posts, is_following=is_following)

    #This function is used to follow the user
    @app.route('/follow', methods=['POST'])
    @user_exists
    @require_login
    @require_not_banned
    def follow():
        if request.method == 'POST':
            user_login = request.form['user_login']
            user = Users.get_user_or_404(user_login)
            follower = Users.get_user_or_404( session['user'])

            if user is None:
                flash("User not found", "error")
            elif user_login == follower.login:
                flash("You can't subscribe to yourself", "error")
            elif follower in user.get_followers_list():
                flash("You are already followers", "error")
            else:
                user.add_follower(follower.login)
                flash("You are now followers", "success")
            return redirect(request.referrer or url_for('index'))
        abort(404)

    #This function is used to unfollow the user
    @app.route('/unfollow', methods=['POST'])
    @user_exists
    @require_login
    @require_not_banned
    def unfollow():
        if request.method == 'POST':
            user_login = request.form['user_login']
            user = Users.get_user_or_404(user_login)
            flower = Users.get_user_or_404(session['user'])

            if user is None:
                flash("User not found", "error")
            elif user_login == flower.login:
                flash("You can't unsubscribe from yourself", "error")
            elif flower not in user.get_followers_list():
                flash("You are not followers", "error")
            else:
                user.delete_follower(flower.login)
                flash("You are not followers anymore", "success")
            return redirect(request.referrer or url_for('index'))
        abort(404)

    #This function is used to edit the group
    @app.route('/groups_setting/<int:id>', methods=['GET', 'POST'])
    @user_exists
    @require_login
    @require_not_banned
    def edit_group(id):
        group = Groups.get_group_or_404(id)
        users_with_roles = group.get_users_with_role_group()

        if  users_with_roles.get(session['user'])  != 'admin':
            flash("You are not an admin of this group", "error")
            return redirect(url_for('group', id=id))

        add_previous_page()
        if request.method == 'POST':
            group_name = request.form['name'].strip()
            group_description = request.form['description'].strip()

            #Validation of the group name and description. Changing only valid data
            if not validate_name(group_name):
                flash("Group name is invalid", "error")
            elif group_name != group.name:
                group.edit_group( request.form['name'], group.description)
                flash("Group name updated", "success")

            if len(group_description) > 60:
                flash("Group description is too long", "error")
            elif group_description != group.description:
                group.edit_group(group.name, request.form['description'])
                flash("Group description updated", "success")

        return render_template("edit_group.html", group=group, users=users_with_roles, posts=group.posts, user = Users.get_user_or_404(session['user']))

    #This function is used to processing various actions with the users in the group
    @app.route('/groups/manage/users', methods=['POST'])
    @user_exists
    @require_login
    @require_not_banned
    def manage_users_group():
        if request.method == 'POST':
            group_id = request.form['group_id']
            user_login = request.form['user_login']
            action = request.form['action']
            group = Groups.get_group_or_404(group_id)

            if action == "delete":
                group.delete_user_group(user_login)
                flash(f"User {user_login} is removed from the group", "success")
            elif action == "make_admin":
                group.make_admin_group(user_login)
                flash(f"User {user_login} is an admin now", "success")
            elif action == "accept_pending":
                group.approve_user_group(user_login)
                flash(f"User {user_login} is a member now", "success")
            elif action == "add":
                group.add_user_group(user_login)
                flash(f"User {user_login} is added to the group", "success")

            return redirect(request.referrer or url_for('edit_group', id=group_id))
        abort(404)

    #This function is used to processing various actions with the posts that bound to the group
    @app.route('/groups/manage/posts', methods=['POST'])
    @user_exists
    @require_login
    @require_not_banned
    def manage_posts_group():
        if request.method == 'POST':
            group_id = request.form['group_id']
            post_id = request.form['post_id']
            action = request.form['action']
            group = Groups.get_group_or_404(group_id)

            if action == "delete":
                Groups.unbind_post_group(group_id, post_id)
                flash("Post deleted", "success")
            return redirect(url_for('edit_group', id=group_id))
        abort(404)

    #This function is used to delete the group
    @app.route('/groups/delete', methods=['POST'])
    @user_exists
    @require_login
    @require_not_banned
    def delete_group():
        if request.method == 'POST':
            flash("Group deleted", "success")
            group_id = request.form['group_id']
            Groups.delete_group(group_id)
            return redirect(url_for('groups'))
        abort(404)

    #This function is used to show received shares
    @app.route('/shares')
    @user_exists
    @require_login
    @require_not_banned
    def shares():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()
        shares_received = Shares.query.filter_by(recipient_login=active_user.login).all()
        return render_template('shares.html', shares=shares_received, user = active_user)

    #This function is used to show sent shares
    @app.route('/shares/sent')
    @user_exists
    @require_login
    @require_not_banned
    def shares_sent():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()
        shares = Shares.query.filter_by(sender_login=active_user.login).all()
        return render_template('shares.html', shares=shares, user = active_user)

    #This function is used to show all users
    @app.route('/users')
    @user_exists
    @require_login
    @require_not_banned
    def users():
        add_previous_page()
        active_user = Users.get_user_or_404(session['user'])

        query = request.args.get('query', '')
        users = [user for user in Users.query.all() if query in user.login or query in user.name or query in user.surname] if query else Users.query.all()
        return render_template('users.html', users=users, user = active_user)

    #This function is used to show followers of the active user
    @app.route('/users/followers')
    @user_exists
    @require_login
    @require_not_banned
    def users_followers():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()

        query = request.args.get('query', '')
        users = [user for user in active_user.get_followers_list() if query in user.login or query in user.name or query in user.surname] if query else active_user.get_followers_list()
        return render_template('users.html', users=users, user = active_user)

    #This function is used to show following of the active user
    @app.route('/users/following')
    @user_exists
    @require_login
    @require_not_banned
    def users_following():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()

        query = request.args.get('query', '')
        users = [user for user in active_user.get_following_list() if query in user.login or query in user.name or query in user.surname] if query else active_user.get_following_list()
        return render_template('users.html', users=users, user = active_user)

    #This function is used to show all groups
    @app.route('/groups')
    @user_exists
    @require_login
    @require_not_banned
    def groups():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()
        query = request.args.get('query', '')
        groups = [group for group in Groups.query.all() if query in group.name] if query else Groups.query.all()

        return render_template('groups.html',groups=groups, user = active_user)

    #This function is used to show groups that the active user is following
    @app.route('/groups/following_groups')
    @user_exists
    @require_login
    @require_not_banned
    def following_groups():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()

        query = request.args.get('query', '')
        groups = [group for group in active_user.groups if query in group.name] if query else active_user.groups
        return render_template('groups.html', groups=groups, user = active_user)

    #This function is used to show groups that the active user is managing
    @app.route('/groups/managed_groups')
    @user_exists
    @require_login
    @require_not_banned
    def managed_groups():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()

        query = request.args.get('query', '')
        groups = [group for group in active_user.managed_groups() if query in group.name] if query else active_user.managed_groups()

        return render_template('groups.html', groups=groups, user = active_user)

    #This function is used to create a new group
    @app.route('/groups/create_group', methods=['POST','GET'])
    @user_exists
    @require_login
    @require_not_banned
    def create_group():
        active_user = Users.get_user_or_404(session['user'])
        if request.method == 'POST':
            group_name = request.form['group-name'].strip()
            group_description = request.form['group-description'].strip()
            bad_data = False
            previous_values = {'group_name': group_name, 'group_description': group_description}

            #Validation of the group name and description. Creating the group if the data is valid
            if not validate_name(group_name):
                flash("Group name is invalid", "error")
                bad_data = True
                previous_values.pop('group_name')

            if len(group_description) > 60:
                flash("Group description is too long", "error")
                bad_data = True
                previous_values.pop('group_description')

            if not bad_data:
                group = Groups.create_group(group_name, group_description, active_user)
                flash("Group created", "success")
                return redirect(url_for('group', id=group.id))
            return render_template('create_group.html', user=active_user, previous_values=previous_values)
        else:

            add_previous_page()
            return render_template('create_group.html', user=active_user, previous_values={})

    #This function is used to show specific group
    @app.route('/groups/<int:id>')
    @user_exists
    @require_login
    @require_not_banned
    def group(id):
        active_user = Users.get_user_or_404(session['user'])
        group = Groups.get_group_or_404(id)
        subscribers_dict = group.get_users_with_role_group()
        add_previous_page()
        is_admin =  subscribers_dict.get(active_user.login) == 'admin'
        return render_template("group.html", group=group, posts = group.posts, is_admin=is_admin, subscribers=subscribers_dict.keys())

    #This function is used to delete user from the database
    @app.route('/delete_user', methods=['POST'])
    @user_exists
    @require_login
    @require_not_banned
    def delete_user():
        if request.method == 'POST':
            user_login = request.form['user_login']
            Users.delete_user(user_login)
            session.pop('user', None)
            flash("User deleted", "success")
            return redirect(url_for('index'))
        abort(404)

    #This function is used to edit user data
    @app.route('/setting/<login>', methods=['GET', 'POST'])
    @user_exists
    @require_login
    @require_not_banned
    def setting(login):

        active_user = Users.get_user_or_404(session['user'])

        if login != active_user.login and active_user.role != 'admin':
            flash("You are not allowed to edit this profile", "error")
            return redirect(url_for('setting', login=active_user.login))

        user = Users.get_user_or_404(login)

        if request.method == 'POST':

            user_name = request.form['name'].strip()
            user_surname = request.form['surname'].strip()

            #Validation of the user name and surname. Changing only valid data
            if not validate_name(user_name, min_size=0):
                flash("Name is invalid", "error")
            elif user_name != user.name:
                flash("Name updated", "success")
                user.change_user_data(name=user_name)

            if not validate_name(user_surname, min_size=0):
                flash("Surname is invalid", "error")
            elif user_surname != user.surname:
                flash("Surname updated", "success")
                user.change_user_data(surname=user_surname)

            #If user is the owner of the profile, he can change the password(not allowed for the admin)
            if login == active_user.login:
                password = request.form['password'].strip()
                confirm_password = request.form['confirm_password'].strip()
                if password:
                    if password == confirm_password and len(password) >= 8:
                        user.change_user_data(password=hashlib.md5(password.encode()).hexdigest())
                        flash("Password updated", "success")
                    else:
                        flash("Passwords do not match and should be at least 8 characters", "error")
        return render_template("edit_profile.html", user=user)

    #This function is used to show the specific post
    @app.route('/posts/<int:post_id>')
    @user_exists
    @require_not_banned
    def post(post_id):
        user_login = session.get('user')

        if user_login is None:
            post = Posts.get_all_posts_by_privacy('public').filter_by(id=post_id).first()
        else:
            active_user = Users.get_user_or_404(user_login)
            #If the user is an admin or a moderator, he can see all the posts
            if active_user.role == 'admin' or active_user.role == 'moderator':
                post = Posts.query.filter_by(id=post_id).first()
            else:
                post = active_user.get_posts_for_user().filter_by(id=post_id).first()

        #If the post is not found, the user is redirected to the previous page
        if post is None:
           return redirect(url_for('go_back'))

        add_previous_page()
        comments = post.comments.all()
        return render_template("post.html", post=post, comments=comments, user=active_user if user_login else None)

    #This function is used to add a new comment to the post
    @app.route('/add_comment/<int:post_id>', methods=['POST'])
    @user_exists
    @require_not_banned
    @require_login
    def add_comment(post_id):
        if request.method == 'POST':
            text = request.form['text']
            if (text == ""):
                flash("Comment is empty", "error")
            elif len(text) > 1000:
                flash("Comment is too long", "error")
            else:
                post = Posts.get_post_or_404(post_id)
                post.add_comment(text, session['user'])
                flash("Comment added", "success")
            return redirect(url_for('post', post_id=post_id))
        abort(404)

    #This function is used to delete the comment from the post
    @app.route('/delete_comment', methods=['POST'])
    @user_exists
    @require_not_banned
    def delete_comment():
        if request.method == 'POST':
            comment = Comments.get_comment_or_404(request.form['comment_id'])
            if comment.author_login == session['user']:
                Comments.delete_comment(request.form['comment_id'])
                flash("Comment deleted", "success")
                return redirect(url_for('post', post_id=comment.post_id))
        abort(404)

    #This function is used to like the post
    @app.route('/like', methods=['POST'])
    @user_exists
    @require_not_banned
    @require_login
    def like_post():
        if request.method == 'POST':
            post_id = request.form['post_id']

            post = Posts.get_post_or_404(post_id)
            user_login = session.get('user')
            post.like_post(user_login)

            return redirect(url_for('post', post_id=post.id))
        abort(404)

    #This function is used to delete the post
    @app.route('/delete_post', methods=['POST'])
    @user_exists
    @require_not_banned
    @require_login
    def delete_post():
        if request.method == 'POST':
            post_id = request.form['post_id']
            post = Posts.get_post_or_404(post_id)
            if post.author_login == session['user']:
                Posts.delete_post(post_id)
                flash("Post deleted", "success")
            return redirect(url_for('go_back'))
        abort(404)

    #This function is used to edit the post
    @app.route('/edit_post/<int:post_id>', methods=['POST', 'GET'])
    @user_exists
    @require_login
    @require_not_banned
    def edit_post(post_id):
        active_user = Users.get_user_or_404(session['user'])
        post = Posts.get_post_or_404(post_id)

        if post.author_login != active_user.login:
            flash("You are not the author of this post", "error")
            return redirect(url_for('post', post_id=post_id))

        if request.method == 'POST':
            tags_input = request.form['tags'].strip()
            tags = [part for tag in tags_input.split('#') if tag for part in tag.split(" ") if part]
            text = request.form['text']
            status = request.form['privacy']
            selected_group = request.form.getlist('groups')
            bad_data = False

            #Validation of the post data. Changing only valid data
            if tags_input and not tags_input.startswith('#'):
                flash("Tags should start with #", "error")
                bad_data = True
            elif len(tags) != tags_input.count('#'):
                bad_data = True
                flash("Tags should be separated by #", "error")
            else:
                post.edit_post(tags=tags)

            for tag in tags:
                if len(tag) > 60:
                    bad_data = True
                    flash("Tag is too long", "error")

            if len(text) > 1000:
                bad_data = True
                flash("Text is too long", "error")
            else:
                post.edit_post(text=text)

            post.edit_post(status=status, selected_groups=selected_group)
            if not bad_data:
                flash("Post updated", "success")
                return redirect(url_for('post', post_id=post.id))

        return render_template("edit_post.html", post = post, user = active_user)

    #This function is used to share the post with the users
    @app.route('/share_post', methods=['POST'])
    @user_exists
    @require_not_banned
    @require_login
    def share_post():
        if request.method == 'POST':
            post_id = request.form['post_id']
            recipient = Users.get_user(request.form['recipient_login'].strip().replace('@', ''))

            post = Posts.get_post_or_404(post_id)
            sender = Users.get_user_or_404(session.get('user'))

            #Validation of the recipient. Sharing the post if the recipient is valid
            if recipient == sender:
                flash("You can't share the post with yourself", "error")
                return redirect(url_for('post', post_id=post.id))
            elif not recipient:
                flash("User not found", "error")
                return redirect(url_for('post', post_id=post.id))

            #Private posts can be shared only with the followers of the author
            if post.status == 'private':
                author = post.author
                if not recipient in author.get_followers_list():
                    flash("You can't share this post with this user", "error")
                    return redirect(url_for('post', post_id=post.id))

            post.share_post(sender.login, recipient.login)
            flash("Post shared", "success")
            return redirect(url_for('post', post_id=post.id))
        abort(404)

    #This function is used to logout the user from the session
    @app.route('/logout')
    def logout():
        if session.get('user') is not None:
            session.pop('user', None)
            flash("You are logged out", "success")
        return redirect(url_for('login'))

    #This function is used to download the image for the post and create the url for the image
    @app.route('/image/<int:id>')
    def image(id):
        if session.get('user') is None:
            img = Posts.get_all_posts_by_privacy('public').filter_by(id=id).first()
        else:
            img = Posts.get_post_or_404(id)
        if img:
            return send_file(io.BytesIO(img.image_binary), mimetype='image/jpeg')
        abort(404)

    #Helper functions for the index page. These functions are used to filter posts
    def filter_posts(results, filter_by, user):
        if filter_by == 'followers':
            return [post for post in results if
                    post.author in user.get_followers_list() and post.author_login != user.login]
        elif filter_by == 'following':
            return [post for post in results if
                    post.author in user.get_following_list() and post.author_login != user.login]
        return results

    #Helper functions for the index page. These functions are used to sort posts
    def sort_posts(results, sort_by):
        if sort_by == 'shares':
            return sorted(results, key=lambda post: post.shares_count(), reverse=True)
        elif sort_by == 'date':
            return sorted(results, key=lambda post: post.date, reverse=True)
        elif sort_by == 'likes':
            return sorted(results, key=lambda post: post.like_count(), reverse=True)
        elif sort_by == 'comments':
            return sorted(results, key=lambda post: post.comments_count(), reverse=True)
        return results

    #This function is used to show the index page with posts feed
    @app.route('/')
    @user_exists
    @require_not_banned
    def index():
        add_previous_page()

        query = request.args.get('query', '').strip().replace(' ', '#')
        sort_by = request.args.get('sort_by', 'date')
        filter_by = request.args.get('filter', 'all')
        tag_list = [tag.strip() for tag in query.split("#") if tag]

        user_login = session.get('user')
        if user_login:
            user = Users.get_user_or_404(user_login)
            results = user.get_posts_for_user_feed()
        else:
            user = None
            results = Posts.get_all_posts_by_privacy('public')

        #Filtering the posts by the tags
        for tag in tag_list:
            results = results.filter(Posts.associated_tags.any(Tags.name == tag))
        results = results.all()

        if user:
            results = filter_posts(results, filter_by, user)
        results = sort_posts(results, sort_by)
        return render_template("index.html", posts=results, user=user)

    #This function is used to show the admin panel with the administration of the users
    @app.route('/admin/users', methods=['GET', 'POST'])
    @user_exists
    @require_login
    @require_not_banned
    @require_admin_or_moder
    def admin_panel_users():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()
        if request.method == 'POST':
            #Processing various actions with the users
            user_login = request.form['user_login']
            action = request.form['action']
            if action == "delete":
                Users.delete_user(user_login)
                flash("User deleted", "success")
            elif action == "make_admin":
                user = Users.get_user_or_404(user_login)
                user.change_user_data(role='admin')
            elif action == "make_user":
                user = Users.get_user_or_404(user_login)
                user.change_user_data(role='user')
            elif action == "make_moderator":
                user = Users.get_user_or_404(user_login)
                user.change_user_data(role='moderator')
            elif action == "ban":
                user = Users.get_user_or_404(user_login)
                user.change_user_data(role='user', is_banned=True)
            elif action == "unban":
                user = Users.get_user_or_404(user_login)
                user.change_user_data(is_banned=False)
            return redirect(request.referrer or url_for('admin_panel_users'))

        #Filtering the users by the login, name, and surname
        query = request.args.get('query', '')
        users = [user for user in Users.query.all() if query in user.login or query in user.name or query in user.surname] if query else Users.query.all()
        return render_template("admin_panel.html", elements=users, panel_type = 'users', user = active_user)

    #This function is used to show the admin panel with the administration of the groups
    @app.route('/admin/groups', methods=['POST', 'GET'])
    @user_exists
    @require_login
    @require_not_banned
    @require_admin_or_moder
    def admin_panel_groups():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()
        if request.method == 'POST':
            #Processing delete group action
            group_id = request.form['group_id']
            Groups.delete_group(group_id)
            flash("Group deleted", "success")
            return redirect(url_for('admin_panel_groups'))

        #Filtering the groups by the name
        query = request.args.get('query', '')
        groups = [group for group in Groups.query.all() if query in group.name] if query else Groups.query.all()
        return render_template("admin_panel.html", elements=groups, panel_type = 'groups', user = active_user)

    #This function is used to show the admin panel with the administration of the posts
    @app.route('/admin/posts', methods=['POST', 'GET'])
    @user_exists
    @require_login
    @require_not_banned
    @require_admin_or_moder
    def admin_panel_posts():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()
        if request.method == 'POST':
            #Processing delete post action
            post_id = request.form['post_id']
            Posts.delete_post(post_id)
            flash("Post deleted", "success")
            return redirect(url_for('admin_panel_posts'))

        #Filtering the posts by the author login
        query = request.args.get('query', '').replace('@', '')
        posts = [post for post in Posts.query.all() if query in post.author_login] if query else Posts.query.all()
        return render_template("admin_panel.html", elements=posts, panel_type = 'posts', user = active_user)

    #This function is used to show the admin panel with the administration of the tags
    @app.route('/admin/tags', methods=['POST', 'GET'])
    @user_exists
    @require_login
    @require_not_banned
    @require_admin_or_moder
    def admin_panel_tags():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()
        if request.method == 'POST':
            #Processing delete tag action
            tag_name = request.form['tag_name'].strip()
            Tags.delete_tag(tag_name)
            flash("Tag deleted", "success")
            return redirect(url_for('admin_panel_tags'))

        #Filtering the tags by the tag name
        query = request.args.get('query', '').replace('#', '')
        tags = [tag for tag in Tags.query.all() if query in tag.name] if query else Tags.query.all()
        return render_template("admin_panel.html", elements=tags, panel_type = 'tags', user = active_user)

    #This function is used to show the admin panel with the administration of the comments
    @app.route('/admin/comments', methods=['POST', 'GET'])
    @user_exists
    @require_login
    @require_not_banned
    @require_admin_or_moder
    def admin_panel_comments():
        active_user = Users.get_user_or_404(session['user'])
        add_previous_page()
        if request.method == 'POST':
            comment_id = request.form['comment_id']
            Comments.delete_comment(comment_id)
            flash("Comment deleted", "success")
            return redirect(url_for('admin_panel_comments'))

        #Filtering the comments by the author login
        query = request.args.get('query', '').replace('@', '')
        comments = [comment for comment in Comments.query.all() if query in comment.author_login] if query else Comments.query.all()
        return render_template("admin_panel.html", elements=comments, panel_type = 'comments', user = active_user)

    #This function is used to create a new post
    @app.route('/create_post', methods=['POST', 'GET'])
    @user_exists
    @require_login
    @require_not_banned
    def create_post():
        active_user = Users.get_user_or_404(session['user'])
        if request.method == 'POST':
            selected_group = list(map(int, request.form.getlist('groups')))
            text = request.form['text'].strip()
            status = request.form['privacy']
            image = request.files.get('image')
            tags_input = request.form['tags'].strip()
            tags = [part for tag in tags_input.split('#') if tag for part in tag.split(" ") if part]
            bad_data = False
            previous_values = {'text': text, 'tags':  request.form['tags'], 'groups': selected_group, 'privacy': status}

            #Validation of the post data. Creating the post if the data is valid
            if tags_input and not tags_input.startswith('#'):
                flash("Tags should start with # and be separated by #", "error")
                bad_data = True
                previous_values.pop('tags')
            elif tags_input and len(tags) != tags_input.count('#'):
                flash("Tags should be separated by #", "error")
                bad_data = True
                previous_values.pop('tags')
            if len(text) > 1000:
                flash("Text is too long", "error")
                bad_data = True
                previous_values.pop('text')

            for tag in tags:
                if len(tag) > 60:
                    bad_data = True
                    flash("Tag is too long", "error")

            if not bad_data:
                flash("Post created", "success")
                Posts.create_post(active_user.login, status, text, transform_images(image),tags, selected_group)
                return redirect(url_for('index'))

            return render_template('create_post.html', user=active_user, previous_values=previous_values)
        else:
            add_previous_page()
            return render_template('create_post.html', user=active_user, previous_values={})

    #This function is used to navigate to the banned page for the banned users
    @app.route('/banned')
    def banned():
        if  session.get('user') is not None:
            active_user = Users.get_user_or_404(session['user'])
            if active_user.is_banned:
                return render_template('banned.html')
        return redirect(url_for('index'))
