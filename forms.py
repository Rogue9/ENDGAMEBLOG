from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField
import email_validator

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Journal Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Posted As", validators=[DataRequired()])
    img_url = StringField("Journal Header Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Journal Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email= StringField("Email", validators=[DataRequired(), Email()])
    password= PasswordField("Password", validators=[DataRequired()])
    submit=SubmitField("Log In")


class CommentForm(FlaskForm):
    comment= CKEditorField("Comment", validators=[DataRequired()])
    author= StringField("Posted As", validators=[DataRequired()])
    submit= SubmitField("Submit Comment")


class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email Address", validators=[DataRequired(), Email()])
    body = StringField("Message", validators=[DataRequired()])
    submit= SubmitField("Send Message")
