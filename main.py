from flask import Flask, render_template, redirect, url_for, flash,request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm
from functools import wraps
from flask_gravatar import Gravatar
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
gravatar = Gravatar(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = db.relationship('BlogPost',back_populates='author')
    comments = db.relationship('Comment', back_populates='comment_author')

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User',back_populates='posts')#db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship('Comment', back_populates='post')

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = db.relationship('User', back_populates='comments')
    text = db.Column(db.Text)
    post = db.relationship('BlogPost',back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


with app.app_context():
    db.create_all()

def admin_only(function):
    @wraps(function)
    def check_user_id(*args,**kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return function(*args, **kwargs)
        else:
            return abort(403)

    return check_user_id

@app.route('/')

def get_all_posts():

    print(current_user.is_authenticated)
    if current_user.is_authenticated and current_user.id == 1:
        admin = True
    else:
        admin = False
    print(admin)
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated,admin=admin)


@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    user = User.query.filter_by(email=request.form.get('email')).first()
    if user:
        flash('Email already exist!, Login instead')
        return redirect(url_for('login'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        hashed_password = generate_password_hash(password,method='pbkdf2:sha256',salt_length=10)
        with app.app_context():
            new_user = User(email=email,name=name,password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            user = User.query.filter_by(password=hashed_password).first()
            login_user(user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html",form=form)


@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    # if current_user.is_authenticated:

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('That email does not exist. Please try again!')
        elif not check_password_hash(user.password,password):
            flash('Password incorrect. Please try again.')
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if current_user.is_authenticated and current_user.id == 1:
        admin = True
    else:
        admin = False
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('You need to login or register to comment.')
            return redirect(url_for('login'))
        else:
            new_comment = Comment(author_id=current_user.id,text=request.form.get('body'),post_id=requested_post.id)
            with app.app_context():
                db.session.add(new_comment)
                db.session.commit()
            return redirect(url_for('get_all_posts'))
    return render_template("post.html", post=requested_post,form=form,admin=admin)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['GET','POST'])
@admin_only
def add_new_post():
    print(current_user.is_authenticated)
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.filter_by(id=post_id).first()
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
