from PIL import Image as PILImage
from app import db, create_app
from models import Users, Groups, Tags, Posts, Comments, Shares, Followers, GroupsUsers, UsersLikePosts, PostsGroups
from faker import Faker
import random
import hashlib
import io
import os

fake = Faker()
app = create_app()


with app.app_context():
    db.drop_all()
    db.create_all()
    def code_password(password):
        return  hashlib.md5(password.encode()).hexdigest()
    def create_users(count=10):
        users = []
        for _ in range(count):
            user = Users(
                login=fake.user_name(),
                mail=fake.email(),
                password=code_password(fake.password()),
                name=fake.first_name(),
                surname=fake.last_name(),
                is_banned=False,
                role=random.choice(['user', 'moderator'])
            )
            users.append(user)
            db.session.add(user)
        db.session.commit()
        return users


    def create_groups(users, count=5):
        groups = []
        for _ in range(count):
            group = Groups(
                name=fake.word(),
                description=fake.text(20)
            )
            groups.append(group)
            db.session.add(group)
        db.session.commit()

        for group in groups:
            for user in random.sample(users, random.randint(1, len(users))):
                db.session.execute(
                    GroupsUsers.insert().values(
                        user_login=user.login,
                        group_id=group.id,
                        role=random.choice(['member', 'admin'])
                    )
                )
        db.session.commit()
        return groups


    def create_tags(count=5):
        tags = []
        for _ in range(count):
            tag = Tags(name=fake.word())
            tags.append(tag)
            db.session.add(tag)
        db.session.commit()
        return tags


    def transform_images(image):
        img = PILImage.open(image)
        img = img.convert('RGB')
        img.thumbnail((600, 600), PILImage.LANCZOS)

        img_io = io.BytesIO()
        img.save(img_io, 'JPEG', quality=100)
        img_io.seek(0)
        return img_io.read()


    def load_photos_from_folder(folder_path):
        photo_files = []
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path) and filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                with open(file_path, 'rb') as photo_file:
                    photo_data = photo_file
                    photo_files.append(transform_images(photo_data))
        return photo_files

    def create_posts(users, groups, tags, count=20):
        posts = []
        images_lst = load_photos_from_folder('static/test_images/')

        for _ in range(count):
            post_status = random.choice(['public', 'private', 'group'])
            post = Posts(
                author_login=random.choice(users).login,
                status=post_status,
                text=fake.text(200),
                image_binary=random.choice(images_lst),
                associated_tags=random.sample(tags, random.randint(1, len(tags)))
            )
            posts.append(post)
            db.session.add(post)
            db.session.commit()

            if post_status == 'group':
                group = random.choice(groups)
                db.session.execute(
                    PostsGroups.insert().values(
                        groups_id=group.id,
                        post_id=post.id
                    )
                )
        db.session.commit()
        return posts


    def create_comments(users, posts, count=20):
        comments = []
        for _ in range(count):
            comment = Comments(
                author_login=random.choice(users).login,
                post_id=random.choice(posts).id,
                text=fake.text(100)
            )
            comments.append(comment)
            db.session.add(comment)
        db.session.commit()
        return comments


    def create_shares(users, posts, count=10):
        shares = []
        for _ in range(count):
            share = Shares(
                sender_login=random.choice(users).login,
                recipient_login=random.choice(users).login,
                post_id=random.choice(posts).id
            )
            shares.append(share)
            db.session.add(share)
        db.session.commit()
        return shares


    def create_followers(users):
        for user in users:
            followers = random.sample([u for u in users if u != user], random.randint(1, len(users) - 1))
            for follower in followers:
                db.session.add(Followers(user_login=user.login, follower_login=follower.login))
        db.session.commit()

    def create_likes(users, posts):
        for post in posts:
            if post.status == 'public':
                likers = random.sample(users, random.randint(1, len(users)))
            else:
                likers = [follower for follower in post.author.followers if follower.user_login != post.author_login]

            for liker in likers:
                db.session.execute(
                    UsersLikePosts.insert().values(
                        user_login=liker.login,
                        post_id=post.id
                    )
                )
        db.session.commit()

    if __name__ == "__main__":
        users = create_users(10)
        groups = create_groups(users, 5)
        tags = create_tags(10)
        posts = create_posts(users, groups, tags, 20)
        comments = create_comments(users, posts, 40)
        shares = create_shares(users, posts, 15)
        create_followers(users)
        create_likes(users, posts)
        Users.add_user('admin', 'admin@admin.com', code_password('adminadmin'), 'admin', 'admin', 'admin')
        Users.add_user('moderator','moderator@moderator.com', code_password('moderatormoderator'), 'moderator', 'moderator', 'moderator')
        Users.add_user('user', 'user@user.com', code_password('useruser'), 'user', 'user', 'user')
        print("Test data created successfully")
