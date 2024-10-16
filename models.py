from app import db

groups_users = db.Table('group_users',
    db.Column('user_login', db.String(60), db.ForeignKey('users.login', ondelete='CASCADE'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
    db.Column('role', db.String(10), nullable=False)
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
    groups = db.relationship('Groups', secondary=groups_users)

    recipient_shares = db.relationship('Shares', backref='recipient',foreign_keys="Shares.recipient_login",
                                cascade="all, delete-orphan",lazy='dynamic')
    send_shares = db.relationship('Shares', backref='sender', foreign_keys="Shares.sender_login",
                                cascade="all, delete-orphan", lazy='dynamic')

    comrades = db.relationship('Comrades', backref='user', foreign_keys="Comrades.user_login", lazy='dynamic',cascade="all, delete-orphan")

class Groups(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True, index=True)
    name = db.Column(db.String(60),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())
    status = db.Column(db.String(10),nullable=False)

    users = db.relationship('Users', secondary=groups_users, viewonly=True)

posts_tags = db.Table('posts_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_name', db.String(60), db.ForeignKey('tags.name', ondelete='CASCADE'), primary_key=True)
)

class Tags(db.Model):
    name = db.Column(db.String(60), primary_key = True)

    associated_post = db.relationship('Posts',secondary=posts_tags, viewonly=True)

UsersLikePosts = db.Table('users_like_posts',
    db.Column('user_login', db.String(60), db.ForeignKey('users.login', ondelete='CASCADE'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), primary_key=True)
)
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    author_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    status = db.Column(db.String(60),nullable=False,)
    text = db.Column(db.String(1000),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())

    image_binary = db.Column(db.LargeBinary,nullable=False)

    associated_tags = db.relationship('Tags', secondary=posts_tags)
    comments = db.relationship('Comments', backref='post', cascade="all, delete-orphan", lazy='dynamic')
    likes = db.relationship('Users', secondary=UsersLikePosts, backref='liked_posts', lazy='dynamic')
    shares = db.relationship('Shares', backref='post', cascade="all, delete-orphan", lazy='dynamic')
    def like_count(self):
        return self.likes.count()

    def shares_count(self):
        return self.shares.count()

    def comments_count(self):
        return self.comments.count()


class Comments(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    author_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'),nullable=False)
    post_id = db.Column(db.Integer,db.ForeignKey('posts.id', ondelete='CASCADE'),nullable=False)
    text = db.Column(db.String(1000),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())

class Shares(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True, index=True)
    posts_id = db.Column(db.Integer,db.ForeignKey('posts.id',ondelete='CASCADE'),nullable=False)
    sender_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    recipient_login = db.Column(db.String(60),db.ForeignKey('users.login', ondelete='CASCADE'),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())
    # post = db.relationship('Posts', single_parent=True)

    shares_sender = db.relationship('Users', single_parent=True, foreign_keys=[sender_login], viewonly=True)
    shares_recipient = db.relationship('Users', single_parent=True, foreign_keys=[recipient_login], viewonly=True)

class Comrades(db.Model):
    user_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'), primary_key = True)
    comrade_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'), primary_key = True)
