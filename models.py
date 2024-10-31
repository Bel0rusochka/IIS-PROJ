from flask import flash

from app import db
from sqlalchemy import or_, and_

GroupsUsers = db.Table('group_users',
    db.Column('user_login', db.String(60), db.ForeignKey('users.login', ondelete='CASCADE'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    db.Column('role', db.String(10), nullable=False, default='member')
)


PostsGroups = db.Table('posts_groups',
    db.Column('groups_id', db.Integer, db.ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), primary_key=True)
)


UsersLikePosts = db.Table('users_like_posts',
    db.Column('user_login', db.String(60), db.ForeignKey('users.login', ondelete='CASCADE'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), primary_key=True)
)


PostsTags = db.Table('posts_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_name', db.String(60), db.ForeignKey('tags.name', ondelete='CASCADE'), primary_key=True)
)


class Users(db.Model):
    login = db.Column(db.String(60), primary_key = True)
    mail = db.Column(db.String(60),nullable=False)
    password = db.Column(db.String(32),nullable=False)
    name = db.Column(db.String(60),nullable=False)
    surname = db.Column(db.String(60),nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(10),nullable=False)

    posts = db.relationship('Posts', backref='author', cascade="all, delete-orphan")
    comments = db.relationship('Comments', backref='author', cascade="all, delete-orphan")
    groups = db.relationship('Groups', secondary=GroupsUsers)

    recipient_shares = db.relationship('Shares', backref='recipient',foreign_keys="Shares.recipient_login",
                                cascade="all, delete-orphan",lazy='dynamic')
    send_shares = db.relationship('Shares', backref='sender', foreign_keys="Shares.sender_login",
                                cascade="all, delete-orphan", lazy='dynamic')

    friends = db.relationship('Friends', backref='user', foreign_keys="Friends.user_login", lazy='dynamic',cascade="all, delete-orphan")
    @staticmethod
    def get_user(login_email):
        return Users.query.filter(or_(Users.login == login_email, Users.mail == login_email)).first()

    @staticmethod
    def get_user_or_404(login):
        return Users.query.get_or_404(login)

    @staticmethod
    def add_user(login,mail,password,name,surname,role):
        user = Users(login=login,mail=mail,password=password,name=name,surname=surname,role=role)
        db.session.add(user)
        db.session.commit()

    @staticmethod
    def delete_user(login):
        user = Users.query.filter_by(login=login).first()
        db.session.delete(user)
        db.session.commit()

    def get_friends_login_list(self):
        return [friend.friend_login for friend in self.friends]

    def get_posts_for_user(self):
        return Posts.query.filter(
            or_(
                Posts.status == "public",
                Posts.status == "group",
                and_(
                    Posts.status == "private",
                    Users.friends.any(
                        and_(
                            Friends.friend_login == self.login,
                            Friends.user_login == Posts.author_login
                        )
                    )
                ),
                and_(
                    Posts.status == "private",
                    Posts.author_login == self.login
                )
            )
        ).order_by(Posts.date.desc())

    def get_posts_for_user_feed(self):
        return self.get_posts_for_user().filter(Posts.status != "group")

    def get_profile_posts(self, active_user_login):
       return self.get_posts_for_user_feed().filter(Posts.author_login == active_user_login).all()

    def get_user_posts_by_privacy(self, privacy):
        match privacy:
            case 'all':
                return Posts.query.filter(Posts.author_login == self.login).all()
            case 'private':
                return Posts.query.filter(Posts.author_login == self.login, Posts.status == 'private').all()
            case 'group':
                return Posts.query.filter(Posts.author_login == self.login, Posts.status == 'group').all()
            case 'not_group':
                return Posts.query.filter(Posts.author_login == self.login, Posts.status != 'group').all()
            case 'not_private':
                return Posts.query.filter(Posts.author_login == self.login, Posts.status != 'private').all()
            case _:
                flash("Invalid request", "error")
                return Posts.query.filter(Posts.author_login == self.login).all()

    def add_friend(self, friend_login):
        friend = Friends(user_login=self.login, friend_login=friend_login)
        db.session.add(friend)
        db.session.commit()

    def delete_friend(self, friend_login):
        friend = Friends.query.filter_by(user_login=self.login, friend_login=friend_login).first()
        db.session.delete(friend)
        db.session.commit()

    def change_user_data(self, name = None, surname = None, password = None):
        if name:
            self.name = name
        if surname:
            self.surname = surname
        if password:
            self.password = password
        db.session.commit()

    def get_friend_to_me(self):
        return [friend.friend_login for friend in self.friends]

    def get_friend_by_me(self):
        friend_by_me = Friends.query.filter_by(friend_login=self.login).all()
        print([friend.user_login for friend in friend_by_me])
        return [friend.user for friend in friend_by_me]


class Groups(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True, index=True)
    name = db.Column(db.String(60),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())
    description = db.Column(db.String(20),nullable=False)
    posts = db.relationship('Posts', secondary=PostsGroups)
    users = db.relationship('Users', secondary=GroupsUsers)

    def is_member(self, login):
        return login in [user.login for user in self.users]

    def post_count(self):
        return len(self.posts)

    def user_count(self):
        print(self.users)
        return len(self.users)

    def get_users_with_role(self):
        return dict(db.session.query(
            GroupsUsers.c.user_login,
            GroupsUsers.c.role
        ).filter(GroupsUsers.c.group_id == self.id).all())

    @staticmethod
    def create_group(name, description, user):
        group = Groups(name=name, description=description)
        group.users.append(user)
        db.session.add(group)
        db.session.commit()
        group.make_admin(user.login)
        return group

    def edit_group(self, name, description):
        self.name = name
        self.description = description
        db.session.commit()

    def delete_group(self):
        db.session.delete(self)
        db.session.commit()

    def make_admin(self, login):
        db.session.execute(
            GroupsUsers.update().values(
                role='admin'
            ).where(and_(GroupsUsers.c.user_login == login, GroupsUsers.c.group_id == self.id))
        )
        db.session.commit()

    @staticmethod
    def get_group_or_404(id):
        return Groups.query.get_or_404(id)

    def delete_member_group(self, user):
        user_posts = [post for post in self.posts if post.author_login == user.login]
        for post in user_posts:
            self.posts.remove(post)
        self.users.remove(user)
        db.session.commit()

    def add_member_group(self, user):
        self.users.append(user)
        db.session.commit()


class Tags(db.Model):
    name = db.Column(db.String(60), primary_key = True)

    associated_post = db.relationship('Posts',secondary=PostsTags, viewonly=True)


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    author_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    status = db.Column(db.String(60),nullable=False,)
    text = db.Column(db.String(1000),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())

    image_binary = db.Column(db.LargeBinary,nullable=False)

    associated_tags = db.relationship('Tags', secondary=PostsTags)
    comments = db.relationship('Comments', backref='post', cascade="all, delete-orphan", lazy='dynamic')
    likes = db.relationship('Users', secondary=UsersLikePosts, backref='liked_posts', lazy='dynamic')
    shares = db.relationship('Shares', backref='post', cascade="all, delete-orphan", lazy='dynamic')

    def like_count(self):
        return self.likes.count()

    def shares_count(self):
        return self.shares.count()

    def comments_count(self):
        return self.comments.count()

    def like_post(self, user_login):
        if self.likes.filter_by(login=user_login).first():
            self.likes.remove(Users.query.filter_by(login=user_login).first())
            db.session.commit()
        else:
            user = Users.query.filter_by(login=user_login).first()
            self.likes.append(user)
            db.session.commit()

    def delete_post(self):
        db.session.delete(self)
        db.session.commit()

    def add_comment(self, text, author_login):
        comment = Comments(author_login=author_login, post_id=self.id, text=text)
        db.session.add(comment)
        db.session.commit()

    def edit_post(self, text, status, tags):
        self.text = text
        self.status = status
        self.associated_tags = tags
        db.session.commit()

    @staticmethod
    def create_post(author_login, status, text, image_binary, tags):
        post = Posts(author_login=author_login, status=status, text=text, image_binary=image_binary)
        for tag in tags:
            if tag == '' or tag == ' ': continue
            tag_db = Tags.query.get(tag)
            if tag_db is None:
                tag_db = Tags(name=tag)
            post.associated_tags.append(tag_db)
        db.session.add(post)
        db.session.commit()

    def share_post(self, sender_login, recipient_login):
        share = Shares(posts_id=self.id, sender_login=sender_login, recipient_login=recipient_login)
        db.session.add(share)
        db.session.commit()
    @staticmethod
    def get_post_or_404(id):
        return Posts.query.get_or_404(id)
    @staticmethod
    def get_all_posts_by_privacy(privacy):
        match privacy:
            case 'all':
                return Posts.query
            case 'public':
                return Posts.query.filter(Posts.status == 'public').order_by(Posts.date.desc())
            case 'private':
                return Posts.query.filter(Posts.status == 'private').order_by(Posts.date.desc())
            case 'group':
                return Posts.query.filter(Posts.status == 'group').order_by(Posts.date.desc())
            case 'not_group':
                return Posts.query.filter(Posts.status != 'group').order_by(Posts.date.desc())
            case _:
                flash("Invalid request", "error")
                return Posts.query.all().order_by(Posts.date.desc())


class Comments(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    author_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'),nullable=False)
    post_id = db.Column(db.Integer,db.ForeignKey('posts.id', ondelete='CASCADE'),nullable=False)
    text = db.Column(db.String(1000),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())

    def get_comment_or_404(id):
        return Comments.query.get_or_404(id)

    def delete_comment(self):
        db.session.delete(self)
        db.session.commit()


class Shares(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True, index=True)
    posts_id = db.Column(db.Integer,db.ForeignKey('posts.id',ondelete='CASCADE'),nullable=False)
    sender_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    recipient_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())
    # post = db.relationship('Posts', single_parent=True)

    shares_sender = db.relationship('Users', single_parent=True, foreign_keys=[sender_login], viewonly=True)
    shares_recipient = db.relationship('Users', single_parent=True, foreign_keys=[recipient_login], viewonly=True)


class Friends(db.Model):
    user_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'), primary_key = True)
    friend_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'), primary_key = True)
