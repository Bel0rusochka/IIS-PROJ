"""
This file contains the models for the database tables.
"""

from flask import flash
from app import db
from sqlalchemy import or_, and_


"""
The following tables are used to create the many-to-many relationships between the tables Groups adn Users.
The table GroupsUsers is used to store the users that are part of a group and their role in that group.
"""
GroupsUsers = db.Table('group_users',
    db.Column('user_login', db.String(60), db.ForeignKey('users.login', ondelete='CASCADE'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    db.Column('role', db.String(10), nullable=False, default='pending')
)


"""
The following tables are used to create the many-to-many relationships between the tables Posts and Groups.
The table PostsGroups is used to store the posts that are bound to a group.
"""
PostsGroups = db.Table('posts_groups',
    db.Column('groups_id', db.Integer, db.ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), primary_key=True)
)


"""
The following tables are used to create the many-to-many relationships between the tables Users and Posts.
The table UsersLikePosts is used to store the likes for a post from a user.
"""
UsersLikePosts = db.Table('users_like_posts',
    db.Column('user_login', db.String(60), db.ForeignKey('users.login', ondelete='CASCADE'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), primary_key=True)
)


"""
The following tables are used to create the many-to-many relationships between the tables Posts and Tags.
The table PostsTags is used to store the tags that are associated with a post.
"""
PostsTags = db.Table('posts_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_name', db.String(60), db.ForeignKey('tags.name', ondelete='CASCADE'), primary_key=True)
)


"""
The following class is used to represent the Users table in the database.
"""
class Users(db.Model):
    login = db.Column(db.String(60), primary_key = True)
    mail = db.Column(db.String(60),nullable=False)
    password = db.Column(db.String(32),nullable=False)
    name = db.Column(db.String(60),nullable=False)
    surname = db.Column(db.String(60),nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(10),nullable=False)

    posts = db.relationship('Posts', backref='author', cascade="all, delete-orphan") #Posts that the user has created
    comments = db.relationship('Comments', backref='author', cascade="all, delete-orphan") #Comments that the user has created
    groups = db.relationship('Groups', secondary=GroupsUsers, viewonly=True) #Groups that the user is part of

    recipient_shares = db.relationship('Shares', backref='recipient',foreign_keys="Shares.recipient_login",
                                cascade="all, delete-orphan",lazy='dynamic') #Shares that the user has received
    send_shares = db.relationship('Shares', backref='sender', foreign_keys="Shares.sender_login",
                                cascade="all, delete-orphan", lazy='dynamic') #Shares that the user has sent

    followers = db.relationship('Followers', backref='user', foreign_keys="Followers.user_login", lazy='dynamic',cascade="all, delete-orphan") #Followers of the user
    following = db.relationship('Followers', backref='follower', foreign_keys="Followers.follower_login", lazy='dynamic',cascade="all, delete-orphan") #Followings of the user

    #The following method is used to get a user from the database by their login or email.
    @staticmethod
    def get_user(login_email):
        return Users.query.filter(or_(Users.login == login_email, Users.mail == login_email)).first()

    #The following method is used to get a user from the database by their login. If the user is not found, a 404 error is raised.
    @staticmethod
    def get_user_or_404(login):
        return Users.query.get_or_404(login)

    #The following method is used to add a user to the database.
    @staticmethod
    def add_user(login,mail,password,name,surname,role):
        user = Users(login=login,mail=mail,password=password,name=name,surname=surname,role=role)
        db.session.add(user)
        db.session.commit()
        return user

    #The following method is used to delete a user from the database.
    @staticmethod
    def delete_user(login):
        user = Users.get_user_or_404(login)
        db.session.delete(user)
        db.session.commit()

    #The following method is used to get the groups that the user is part of.
    def get_approved_groups(self):
        groups = [group for group in self.groups if group.get_users_with_role_group().get(self.login) != 'pending']
        return groups

    #The following method is used to get the posts that the user can see based on their privacy settings, also taking into account the private posts of the users that the user follows.
    def get_posts_for_user(self):
        return Posts.query.filter(
            or_(
                Posts.status == "public",
                Posts.status == "group",
                and_(
                    Posts.status == "private",
                    Users.followers.any(
                        and_(
                            Followers.follower_login == self.login,
                            Followers.user_login == Posts.author_login
                        )
                    )
                ),
                and_(
                    Posts.status == "private",
                    Posts.author_login == self.login
                )
            )
        ).order_by(Posts.date.desc())

    #The same as the previous method, but without the group posts.
    def get_posts_for_user_feed(self):
        return self.get_posts_for_user().filter(Posts.status != "group")

    #The following method is used to get the posts that the user has created.
    def get_profile_posts(self, active_user_login):
       return self.get_posts_for_user_feed().filter(Posts.author_login == active_user_login).all()

    #The following method is used to get the posts based on the privacy argument.
    def get_user_posts_by_privacy(self, privacy):
            privacy_filters = {
                'all': Posts.author_login == self.login,
                'private': and_(Posts.author_login == self.login, Posts.status == 'private'),
                'group': and_(Posts.author_login == self.login, Posts.status == 'group'),
                'not_group': and_(Posts.author_login == self.login, Posts.status != 'group'),
                'not_private': and_(Posts.author_login == self.login, Posts.status != 'private'),
            }
            filter_condition = privacy_filters.get(privacy)
            if filter_condition is None:
                flash("Invalid request", "error")
                return []
            return Posts.query.filter(filter_condition).all()

    #The following method is used to add a follower to the user.
    def add_follower(self, follower_login):
        follower = Followers(user_login=self.login, follower_login=follower_login)
        db.session.add(follower)
        db.session.commit()

    #The following method is used to delete a follower from the user.
    def delete_follower(self, follower_login):
        follower = Followers.query.filter_by(user_login=self.login, follower_login=follower_login).first()
        db.session.delete(follower)
        db.session.commit()

    #The following method is used to change the data of the user.
    def change_user_data(self, **kwargs):
        for key, value in kwargs.items():
            print(key, value)
            if hasattr(self, key) and value is not None:
                setattr(self, key, value)
        db.session.commit()

    #The following method is used to get the followers of the user.
    def get_followers_list(self):
        return [Users.get_user(follower.follower_login) for follower in self.followers]

    #The following method is used to get the following of the user.
    def get_following_list(self):
        return [Users.get_user(following.user_login) for following in self.following]

    #The following method is used to get the number of followers of the user. Used in the html templates.
    def get_followers_count(self):
        return len(self.followers.all())

    #The following method is used to get the number of following of the user. Used in the html templates.
    def get_following_count(self):
        return len(self.following.all())

    #The following method is used to get the number of posts of the user. Used in the html templates.
    def get_posts_count(self):
        return len(self.posts)

    #The following method is used to get the number of groups where the user is an admin.
    def managed_groups(self):
        admin_groups = []

        for group in self.groups:
            group_user = db.session.query(GroupsUsers).filter_by(user_login=self.login, group_id=group.id).first()
            if group_user and group_user.role == 'admin':
                admin_groups.append(group)

        return admin_groups


"""
The following class is used to represent the Groups table in the database.
"""
class Groups(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True, index=True)
    name = db.Column(db.String(60),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())
    description = db.Column(db.String(60),nullable=False)
    posts = db.relationship('Posts', secondary=PostsGroups, order_by='Posts.date.desc()') #Posts that are bound to the group
    users = db.relationship('Users', secondary=GroupsUsers)  #Users that are part of the group

    #The following method is used to get a group from the database by its id. If the group is not found, a 404 error is raised.
    @staticmethod
    def get_group_or_404(id):
        return Groups.query.get_or_404(id)

    #The following method is used to create a group in the database.
    @staticmethod
    def create_group(name, description, user):
        group = Groups(name=name, description=description)
        group.users.append(user)
        db.session.add(group)
        db.session.commit()
        group.make_admin_group(user.login)
        return group

    #The following method is used to delete a group from the database.
    @staticmethod
    def delete_group(id):
        group = Groups.query.get(id)
        db.session.delete(group)
        db.session.commit()

    #The following method is used to unbind a selected post from a group.
    @staticmethod
    def unbind_post_group(group_id, post_id):
        db.session.execute(
            PostsGroups.delete().where(and_(PostsGroups.c.post_id == post_id, PostsGroups.c.groups_id == group_id))
        )
        db.session.commit()

    #The following method is used to bind a selected post to a group.
    @staticmethod
    def bind_post_group(group_id, post_id):
        db.session.execute(
            PostsGroups.insert().values(
                post_id=post_id,
                groups_id=group_id
            )
        )
        db.session.commit()

    #The following method is used to check if a user is subscribed to a group.
    def is_subscribed(self, login):
        return login in [user.login for user in self.users ]

    #The following method is used to get the count of posts that are bound to the group. Used in the html templates.
    def posts_count(self):
        return len(self.posts)

    #The following method is used to get the count of members that are part of the group. Used in the html templates.
    def members_count(self):
        members = [user for user in self.users if user.role != 'pending']
        return len(members)

    #The following method is used to get all the users that are part of the group and their role in the group.
    def get_users_with_role_group(self):
        return dict(db.session.query(
            GroupsUsers.c.user_login,
            GroupsUsers.c.role
        ).filter(GroupsUsers.c.group_id == self.id).all())

    #The following method is used to edit the group data.
    def edit_group(self, name, description):
        self.name = name
        self.description = description
        db.session.commit()

    #The following method is used to make a user an admin of the group.
    def make_admin_group(self, login):
        db.session.execute(
            GroupsUsers.update().values(
                role='admin'
            ).where(and_(GroupsUsers.c.user_login == login, GroupsUsers.c.group_id == self.id))
        )
        db.session.commit()

    #The following method is used to delete a user from the group.
    def delete_user_group(self, user_login):
        user = Users.query.get(user_login)
        user_posts = [post for post in self.posts if post.author_login == user.login]
        for post in user_posts:
            self.posts.remove(post)
        self.users.remove(user)
        db.session.commit()

    #The following method is used to add a user to the group.
    def add_user_group(self, user_login):
        user = Users.query.get(user_login)
        self.users.append(user)
        db.session.commit()

    #The following method is used to approve a user to be a member of the group not a pending user.
    def approve_user_group(self, login):
        db.session.execute(
            GroupsUsers.update().values(
                role='member'
            ).where(and_(GroupsUsers.c.user_login == login, GroupsUsers.c.group_id == self.id))
        )
        db.session.commit()


"""
The following class is used to represent the Tags table in the database.
"""
class Tags(db.Model):
    name = db.Column(db.String(60), primary_key = True)

    associated_post = db.relationship('Posts',secondary=PostsTags, viewonly=True) #Posts that are associated with the tag

    #The following method is used to delete a tag from the database.
    @staticmethod
    def delete_tag(name):
        tag = Tags.query.get(name)
        db.session.delete(tag)
        db.session.commit()

    #The following method is used to get the count of posts that are associated with the tag. Used in the html templates.
    def posts_count(self):
        return len(self.associated_post)


"""
The following class is used to represent the Posts table in the database.
"""
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    author_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    status = db.Column(db.String(60),nullable=False,)
    text = db.Column(db.String(1000),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())
    image_binary = db.Column(db.LargeBinary,nullable=False)

    associated_tags = db.relationship('Tags', secondary=PostsTags) #Tags that are associated with the post
    comments = db.relationship('Comments', backref='post', cascade="all, delete-orphan", lazy='dynamic') #Comments that are bound to the post
    likes = db.relationship('Users', secondary=UsersLikePosts, backref='liked_posts', lazy='dynamic') #Users that have liked the post
    shares = db.relationship('Shares', backref='post', cascade="all, delete-orphan", lazy='dynamic') #Shares that are bound to the post

    #The following method is used to get a post from the database by its id. If the post is not found, a 404 error is raised.
    @staticmethod
    def get_post_or_404(id):
        return Posts.query.get_or_404(id)

    #The following method is used to get all the posts from the database based on the privacy argument.
    @staticmethod
    def get_all_posts_by_privacy(privacy):
        privacy_filters = {
            'public': Posts.status == 'public',
            'private': Posts.status == 'private',
            'group': Posts.status == 'group',
            'not_group': Posts.status != 'group'
        }

        filter_condition = privacy_filters.get(privacy)

        if filter_condition is None and privacy != 'all':
            flash("Invalid request", "error")
            return Posts.query.order_by(Posts.date.desc())


        query = Posts.query.filter(filter_condition) if filter_condition is not None else Posts.query
        return query.order_by(Posts.date.desc())

    #The following method is used to create a post in the database.
    @staticmethod
    def create_post(author_login, status, text, image_binary, tags, groups_id):
        post = Posts(author_login=author_login, status=status, text=text, image_binary=image_binary)
        for tag in set(tags):
            tag = tag.strip()
            if tag == '' or tag == ' ': continue
            tag_db = Tags.query.get(tag)
            if tag_db is None:
                tag_db = Tags(name=tag)
            post.associated_tags.append(tag_db)

        db.session.add(post)
        db.session.commit()

        if status == 'group' and len(groups_id) > 0:
            for group_id in groups_id:
                Groups.bind_post_group(group_id, post.id)

    #The following method is used to delete a post from the database.
    @staticmethod
    def delete_post(id):
        post = Posts.query.get(id)
        db.session.delete(post)
        db.session.commit()

    #The following method is used to get the groups that the post is bound to.
    def get_connected_groups(self):
        groups = db.session.query(PostsGroups).filter_by(post_id=self.id).all()
        return [Groups.query.get(group.groups_id) for group in groups]

    #The following method is used to get the count of likes that the post has. Used in the html templates.
    def like_count(self):
        return self.likes.count()

    #The following method is used to get the count of shares that the post has. Used in the html templates.
    def shares_count(self):
        return self.shares.count()

    #The following method is used to get the count of comments that the post has. Used in the html templates.
    def comments_count(self):
        return self.comments.count()

    #The following method is used add or remove a like from the post.
    def like_post(self, user_login):
        if self.likes.filter_by(login=user_login).first():
            self.likes.remove(Users.query.filter_by(login=user_login).first())
            db.session.commit()
        else:
            user = Users.query.filter_by(login=user_login).first()
            self.likes.append(user)
            db.session.commit()

    #The following method is used to add a comment to the post.
    def add_comment(self, text, author_login):
        comment = Comments(author_login=author_login, post_id=self.id, text=text)
        db.session.add(comment)
        db.session.commit()

    #The following method is used to edit the post data.
    def edit_post(self, text=None, status=None, tags=None, selected_groups=None):
        if text is not None:
            self.text = text

        if tags is not None:
            associated_tags = []
            for tag in set(tags):
                tag = tag.strip()
                if tag == '' or tag == ' ': continue
                tag_db = Tags.query.get(tag)
                if tag_db is None:
                    tag_db = Tags(name=tag)
                associated_tags.append(tag_db)
            self.associated_tags = associated_tags

        if status is not None:
            if self.status == 'group' and status != 'group':
                groups = db.session.query(PostsGroups).filter_by(post_id=self.id).all()
                for group in groups:
                    Groups.unbind_post_group(group.groups_id, self.id)
            self.status = status

        if self.status == 'group' and selected_groups is not None:
            groups = db.session.query(PostsGroups).filter_by(post_id=self.id).all()
            for group in groups:
                Groups.unbind_post_group(group.groups_id, self.id)
            for group_id in selected_groups:
                Groups.bind_post_group(group_id, self.id)
        db.session.commit()

    #The following method is used to share the post with another user.
    def share_post(self, sender_login, recipient_login):
        share = Shares(post_id=self.id, sender_login=sender_login, recipient_login=recipient_login)
        db.session.add(share)
        db.session.commit()


"""
The following class is used to represent the Comments table in the database.
"""
class Comments(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    author_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'),nullable=False)
    post_id = db.Column(db.Integer,db.ForeignKey('posts.id', ondelete='CASCADE'),nullable=False)
    text = db.Column(db.String(1000),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())

    #The following method is used to get a comment from the database by its id. If the comment is not found, a 404 error is raised.
    @staticmethod
    def get_comment_or_404(id):
        return Comments.query.get_or_404(id)

    #The following method is used to delete a comment from the database.
    @staticmethod
    def delete_comment(id):
        comment = Comments.query.get(id)
        db.session.delete(comment)
        db.session.commit()


"""
The following class is used to represent the Shares table in the database.
The Shares table is used to create the many-to-many relationship between the Users table and the Posts table.
"""
class Shares(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True, index=True)
    post_id = db.Column(db.Integer,db.ForeignKey('posts.id',ondelete='CASCADE'),nullable=False)
    sender_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    recipient_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())

    shares_sender = db.relationship('Users', single_parent=True, foreign_keys=[sender_login], viewonly=True) #The user that has sent the share to another user
    shares_recipient = db.relationship('Users', single_parent=True, foreign_keys=[recipient_login], viewonly=True) #The user that has received the share


"""
The following class is used to represent the Followers table in the database.
Followers is a table that is used to create the many-to-many relationship between the Users table.
"""
class Followers(db.Model):
    user_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'), primary_key = True)
    follower_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'), primary_key = True)