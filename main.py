import os
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # One-to-many bidirectional relationship with User table
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    author: Mapped["User"] = relationship(back_populates="posts")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    comments: Mapped[list["Comment"]] = relationship(back_populates="parent_post")


# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)

    posts: Mapped[list["BlogPost"]] = relationship(back_populates="author")
    comments : Mapped[list["Comment"]] = relationship(back_populates="author")


# Comment table so users can add comments to blog posts
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    author: Mapped["User"] = relationship(back_populates="comments")

    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    parent_post: Mapped["BlogPost"] = relationship(back_populates="comments")


with app.app_context():
    db.create_all()

# CODE TO GET THE AVATAR FROM GRAVATAR WITHOUT THE FLASK-GRAVATAR EXTENSION
# GRAVATAR_API_KEY = "5596:gk-1ZnQUnhrQNPyyPQmx8n4kjgLuVWXzAB4MJiW7papjCJh56pPePprpacQGamS1"
# GRAVATAR_BASE_URL = "https://api.gravatar.com/v3"
# GRAVATAR_AVATAR_URL = "https://www.gravatar.com/avatar"
#
# def get_gravatar_hash(email):
#     email_encoded = str(email).lower().encode('utf-8')
#     email_hash = hashlib.sha256(email_encoded).hexdigest()
#     return email_hash
#
# def get_gravatar_image(email):
#     email_hashed = get_gravatar_hash(email)
#     size = "100"
#     query_params = urlencode({'d': default, 's': str(size)})
#     gravatar_url = f"{GRAVATAR_AVATAR_URL}/{email_hashed}?{query_params}"
#     return gravatar_url


# FLASK-GRAVATAR EXTENSION TO GET THE AVATARS
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        hashed_password = generate_password_hash(
            register_form.password.data,
            method="pbkdf2:sha256",
            salt_length=8
        )
        new_user = User(
            email=register_form.email.data,
            password = hashed_password,
            name = register_form.name.data
        )
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That email is already registered. Please log in instead.")
            return redirect(url_for('login'))
        else:
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form, current_user=current_user)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        is_user = db.session.execute(db.select(User).where(User.email == login_form.email.data)).scalar()

        if not is_user:
            flash("That email does not exist in our database, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(is_user.password, login_form.password.data):
            flash("Incorrect password, please try again.")
            return redirect(url_for('login'))
        else:
            login_user(is_user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form, current_user=current_user)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return f(*args, **kwargs)
        return abort(403)
    return decorated_function


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    # CODE TO PASS A DICTIONARY OF AVATARS TO THE post.html
    # commenter_images = {}
    # for comment in requested_post.comments:
    #     image_url = get_gravatar_image(comment.author.email)
    #     response = requests.get(image_url)
    #     if response.status_code == 200:
    #         commenter_images[comment.author.email] = get_gravatar_image(comment.author.email)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please log in if you want to add a comment.")
            return redirect(url_for('login'))
        new_comment = Comment(
            text = comment_form.comment.data,
            author_id = current_user.id,
            author = current_user,
            post_id = post_id,
            parent_post = requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        # Redirect so if the page gets reloaded the POST request is not repeated, only the GET request
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", form=comment_form, post=requested_post, current_user=current_user)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    post_form = CreatePostForm()
    if post_form.validate_on_submit():
        new_post = BlogPost(
            title=post_form.title.data,
            subtitle=post_form.subtitle.data,
            body=post_form.body.data,
            img_url=post_form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=post_form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=False)
