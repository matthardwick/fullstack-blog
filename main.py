import webapp2
import os
import string
import random
import re
import hmac
# import logging
# import time
import jinja2
# import datetime
# from pytz import timezone
# import pytz
from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


SECRET = 'Udacity'


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        params['user'] = self.user
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookies(self, name, value):
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, value))

    def read_user_id(self):
        secure_user_id = self.request.cookies.get('user_id')
        if secure_user_id:
            if validate_cookie_user_id(secure_user_id):
                user_id = secure_user_id.split('|')[0]
            else:
                user_id = None
        else:
            user_id = None
        return user_id

    # Get integer after the last '/' in url as the post_id
    def get_id_from_url(self):
        url = self.request.url
        post_id = url.rsplit('/', 1)[-1]
        return post_id

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_user_id()
        if user_id:
            self.user = User.get_by_id(int(user_id), parent=users_key())
        else:
            self.user = None


def blog_key(name='default'):
    return ndb.Key('blogs', name)


class Post(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    author_key = ndb.KeyProperty(kind='User', required=True)
    liked_by = ndb.KeyProperty(kind='User', repeated=True)
    likes = ndb.IntegerProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    @property
    def comments(self):
        return Comment.query().filter(Comment.post_key == self.key).fetch()


class Comment(ndb.Model):
    content = ndb.TextProperty(required=True)
    post_key = ndb.KeyProperty(kind='Post', required=True)
    updated = ndb.DateTimeProperty(auto_now=True)


class MainPage(Handler):

    def get(self):
        posts = Post.query(ancestor=blog_key()).order(-Post.created).fetch()
        previous_url = self.request.url
        self.render("blog.html", posts=posts, previous_url=previous_url)


class NewPost(Handler):

    def get(self):
        if self.user:
            self.render("post_form.html")
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/login')
            return

        subject = self.request.get('subject')
        content = self.request.get('content')
        if not subject or not content:
            self.render("post_form.html",
                        heading="New Post",
                        error="subject and content please")
        else:
            post = Post(subject=subject, content=content,
                        author_key=self.user.key, parent=blog_key())
            post_key = post.put()
            self.redirect('/post/' + str(post_key.id()))


class SinglePostPage(Handler):

    def get(self):
        # Get post_id from url
        post_id = self.get_id_from_url()
        # query post by id
        post = Post.get_by_id(int(post_id), parent=blog_key())
        current_user_key = None
        if self.user:
            current_user_key = self.user.key
        if not post:
            self.error(404)
            return
        else:
            self.render("post.html", post=post,
                        current_user_key=current_user_key)


class EditPost(Handler):

    def get(self):
        if not self.user:
            self.redirect('/login')
            return
        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not post:
            self.error(404)
            return
        if post.author_key != self.user.key:
            self.redirect('/edit/error')
        else:
            subject = post.subject
            content = post.content
            self.render("post_form.html",
                        heading="Edit Post",
                        subject=subject,
                        content=content,
                        previous_url=self.request.referer)

    def post(self):
        if not self.user:
            self.redirect('/login')
            return
        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not post:
            self.error(404)
            return
        if post.author_key != self.user.key:
            self.redirect('/edit/error')
        else:
            # Get the subject and content on the Edit Form
            new_subject = self.request.get('subject')
            new_content = self.request.get('content')
            if not new_subject or not new_content:
                self.render("post_form.html",
                            heading="Edit Post",
                            subject=new_subject,
                            content=new_content,
                            previous_url=self.request.referer,
                            error="subject and content please")
                return
            updated = False
            if post.subject != new_subject:
                post.subject = new_subject
                updated = True
            if post.content != new_content:
                post.content = new_content
                updated = True
            if updated:
                post.put()
            self.redirect('/post/' + post_id)


class EditPostError(Handler):

    def get(self):
        self.render(
            "error.html",
            error_message="You don't have permission to edit this post")


class DeletePost(Handler):

    def get(self):
        if not self.user:
            self.redirect('/login')
            return
        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not post:
            error(404)
            return
        if post.author_key != self.user.key:
            self.redirect('/post/delete/error')
        else:
            post.key.delete()
            self.redirect('/')


class DeletePostError(Handler):

    def get(self):
        self.render(
            "error.html",
            error_message="You don't have permission to delete this post")


class LikePost(Handler):

    def get(self):
        if not self.user:
            self.redirect('/login')
            return

        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not post:
            error(404)
            return

        if self.user.key in post.liked_by:
            # toggle like/unlike
            self.unlike(post)
            self.redirect('/')
        else:
            if post.author_key == self.user.key:
                self.redirect('/like/error')
            else:
                self.like(post)
                self.redirect(self.request.referer)

    def unlike(self, post):
        post.liked_by.remove(self.user.key)
        post.likes -= 1
        post.put()

    def like(self, post):
        post.liked_by.append(self.user.key)
        post.likes += 1
        post.put()


class LikeError(Handler):

    def get(self):
        self.render(
            "error.html", error_message="You can not like your own posts")


class CommentPost(Handler):

    def get(self):
        if not self.user:
            self.redirect('/login')
            return
        self.render("comment.html", previous_url=self.request.referer)

    def post(self):
        if not self.user:
            self.redirect('/login')
            return

        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not post:
            self.render("error.html",
                        previous_url=self.request.referer,
                        error="No post was found")
            return

        content = self.request.get('content')
        if not content:
            self.render("comment.html",
                        previous_url=self.request.referer,
                        error="Can't leave an empty comment!")
        else:
            comment = Comment(
                content=content, post_key=post.key, parent=self.user.key)
            comment.put()
            self.redirect('/post/' + str(post.key.id()))


class EditComment(Handler):

    def get(self):
        if not self.user:
            self.redirect('/login')
            return
        comment_id = self.get_id_from_url()
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key)
        # Check if user is editing own comment
        if comment:
            content = comment.content
            self.render("comment.html",
                        previous_url=self.request.referer,
                        content=content)
        else:
            self.render(
                "error.html",
                error_message="You do not have permission to edit or delete other comments")

    def post(self):
        if not self.user:
            self.redirect('/login')

        comment_id = self.get_id_from_url()
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key)
        if not comment:
            error(404)
            return
        new_content = self.request.get('content')
        updated = False
        if new_content != comment.content:
            updated = True
            comment.content = new_content
        if updated:
            comment.put()
        self.redirect('/post/' + str(comment.post_key.id()))


class DeleteComment(Handler):

    def get(self):

        if not self.user:
            self.redirect('/login')
            return
        comment_id = self.get_id_from_url()
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key)
        if not comment:
            self.redirect('/deletecomment/error')
        else:
            comment.key.delete()
            self.redirect(self.request.referer)


class DeleteCommentError(Handler):

    def get(self):
        self.render(
            "error.html",
            error_message="You don't have permission to delete this post")


def validate_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)


def validate_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return PASSWORD_RE.match(password)


def compare_passwords(password, verify):
    if password:
        if password == verify:
            return True
        else:
            return False
    else:
        return False


def validate_email(email):
    if email:
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return EMAIL_RE.match(email)
    else:
        return True


def make_salt():
    return ''.join((random.choice(string.letters)) for i in range(5))


def make_secure_pw(username, password, salt=make_salt()):
    hash_value = hmac.new(SECRET, username + password + salt).hexdigest()
    return "%s,%s" % (hash_value, salt)


def make_secure_cookie_user_id(user_id):
    hash_value = hmac.new(SECRET, str(user_id)).hexdigest()
    return "%s|%s" % (user_id, hash_value)


def validate_cookie_user_id(secure_user_id):
    split_value = secure_user_id.split("|")
    if len(split_value) != 2:
        return False
    user_id = split_value[0]
    if hmac.new(SECRET, user_id).hexdigest() == split_value[1]:
        return True
    else:
        return False


def users_key(group='default'):
    return ndb.Key('users', group)


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)


class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        # validate signup form
        if (validate_username(username)
                and validate_password(password)
                and compare_passwords(password, verify)
                and validate_email(email)):
            self.register(username, password, email)
        else:
            if not validate_username(username):
                username_error = "That's not a valid username"

            if not validate_password(password):
                password_error = "That's not a valid password"
            elif not compare_passwords(password, verify):
                verify_error = "Your passwords didn't match"

            if not validate_email(email):
                email_error = "That's not a valid email"

            self.render("signup.html", username=username,
                        username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email_error=email_error)

    def register(self, username, password, email):
        user = User.query(User.username == username).get()
        if user:
            self.render("signup.html",
                        username_error="That user already exists")
            return
        secure_password = make_secure_pw(username, password)
        user = User(username=username, password=secure_password,
                    email=email, parent=users_key())
        user_key = user.put()
        user_id = user_key.id()
        secure_user_id = make_secure_cookie_user_id(str(user_id))
        self.set_cookies('user_id', secure_user_id)
        self.redirect('/welcome')


class Login(Handler):

    def get(self):
        self.render("login.html")

    def post(self):

        username = self.request.get('username')
        password = self.request.get('password')

        if username and password:
            user = User.query(User.username == username,
                              ancestor=users_key()).get()
            if user:
                password_db = user.password
                if Login.check_password(username, password, password_db):
                    secure_user_id = make_secure_cookie_user_id(user.key.id())
                    self.set_cookies('user_id', secure_user_id)
                    self.redirect('/welcome')
                else:
                    self.render("login.html", username=username,
                                login_error="Invalid Login")
            else:
                self.render("login.html", username=username,
                            login_error="Invalid Login")
        else:
            self.render("login.html", username=username,
                        login_error="Username and Password Can't be Blank")

    @staticmethod
    def check_password(username, password, password_db):
        split_value = password_db.split(',')
        salt = split_value[1]
        secure_password = make_secure_pw(username, password, salt)
        if secure_password == password_db:
            return True
        else:
            return False


class Logout(Handler):

    def get(self):
        self.set_cookies('user_id', '')
        self.redirect('/')


class WelcomePage(Handler):

    def get(self):
        user_id = self.read_user_id()
        if user_id:
            username = User.get_by_id(
                int(user_id), parent=users_key()).username
            if username:
                self.render("welcome.html", username=username)
            else:
                self.redirect('/signup')
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', NewPost),
                               ('/post/edit/[0-9]+', EditPost),
                               ('/delete/[0-9]+', DeletePost),
                               ('/post/delete/error', DeletePostError),
                               ('/edit/error', EditPostError),
                               ('/post/[0-9]+', SinglePostPage),
                               ('/login', Login),
                               ('/signup', Signup),
                               ('/logout', Logout),
                               ('/welcome', WelcomePage),
                               ('/like/[0-9]+', LikePost),
                               ('/like/error', LikeError),
                               ('/newcomment/[0-9]+', CommentPost),
                               ('/editcomment/[0-9]+', EditComment),
                               ('/deletecomment/[0-9]+', DeleteComment),
                               ('/deletecomment/error', DeleteCommentError)
                               ], debug=True)
