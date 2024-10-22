from app import db

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

    viewers = db.relationship('Viewers', backref='user', foreign_keys="Viewers.user_login", lazy='dynamic',cascade="all, delete-orphan")


class Groups(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement=True, index=True)
    name = db.Column(db.String(60),nullable=False)
    date = db.Column(db.DateTime,default=db.func.current_timestamp())
    description = db.Column(db.String(20),nullable=False)
    posts = db.relationship('Posts', secondary=PostsGroups, viewonly=True)
    users = db.relationship('Users', secondary=GroupsUsers)

    def post_count(self):
        return len(self.posts)
    def users_with_role(self):
        return dict(db.session.query(
            GroupsUsers.c.user_login,
            GroupsUsers.c.role
        ).filter(GroupsUsers.c.group_id == self.id).all())

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


class Viewers(db.Model):
    user_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'), primary_key = True)
    viewer_login = db.Column(db.String(60),db.ForeignKey('users.login',ondelete='CASCADE'), primary_key = True)
