from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ContactForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import ForeignKey
import smtplib
import os
EMAIL = "bulby37@gmail.com"
PASSWORD = os.environ.get("EMAIL_PASS")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite://blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__= "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")
    character_name= db.Column(db.String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text= db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    comment_author = relationship("User", back_populates="comments")
    parent_post = relationship("BlogPost", back_populates="comments")
    character_name= db.Column(db.String(250), nullable=False)


class Campaign(db.Model):
    __tablename__ = "campaigns"
    id = db.Column(db.Integer, primary_key=True)
    group_name=db.Column(db.String(100))
    setting=db.Column(db.String(100), nullable=False)
db.create_all()

gravatar = Gravatar(app,
                    size=100,
                    rating='pg',
                    default='monsterid',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id > 4:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("That email is already registered, log in instead")
            return redirect(url_for("login"))
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data.lower(),
            name=form.name.data.title(),
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts", logged_in=current_user.is_authenticated))
    return render_template("register.html", form=form, current_user=current_user)


login_manager= LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email= form.email.data.lower()
        password= form.password.data
        user= User.query.filter_by(email=email).first()
        if not user:
            flash("That email is not registered, try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, try again")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts", current_user=current_user))

    return render_template("login.html", form=form, current_user=current_user)


@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments= Comment.query.filter_by(post_id=post_id).all()
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("You have to log in before you can comment!")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(
                text= comment_form.comment.data,
                author_id = current_user.id,
                post_id = post_id,
                character_name = comment_form.author.data
            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, form=comment_form, comments=comments)


    return render_template("post.html", post=requested_post, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route('/contact', methods=["GET", "POST"])

def contact():
    form= ContactForm()
    if form.validate_on_submit():
        send_email(form.name.data, form.email.data, form.body.data)
        return redirect(url_for("get_all_posts", current_user=current_user, msg_sent=True))
    return render_template('contact.html', form=form, current_user=current_user, msg_sent=False)


def send_email(name, email, message):
    with smtplib.SMTP('smtp.gmail.com', port=587) as connection:
        connection.starttls()
        connection.login(EMAIL, PASSWORD)
        connection.sendmail(from_addr=f'{email}',
                            to_addrs='JRLEWIS84@GMAIL.COM',
                            msg=f"Subject:Message from Adventurer's Journal User\n\n{name}\n{email}\n{message}")
    return redirect(url_for("get_all_posts", current_user=current_user, msg_sent=True))


@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm(
        img_url="https://images.unsplash.com/photo-1619075120066-02024cb853bd?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1351&q=80"
    )
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            author_id= current_user.id,
            date=date.today().strftime("%B %d, %Y"),
            character_name=form.author.data
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.character_name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        post.character_name = edit_form.author.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, current_user=current_user))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', current_user=current_user))

@app.route("/user_purge/<int:user_id>")
@login_required
@admin_only
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', current_user=current_user))

@app.route("/comment_purge/<int:comment_id>")
@login_required
@admin_only
def delete_comment(comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', current_user=current_user))

@app.route("/admin")
@login_required
@admin_only
def admin_panel():
    users = User.query.all()
    posts = BlogPost.query.all()
    comments = Comment.query.all()
    return render_template("admin.html", all_posts=posts, all_users=users, all_comments=comments, current_user=current_user)


@app.route("/name-card")
def name_card():
    return render_template("card.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
