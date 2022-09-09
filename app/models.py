# Database related imports
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.sql import func

# Form related imports
from wtforms import StringField, PasswordField, SubmitField, FileField, EmailField, TextAreaField, RadioField, HiddenField
from wtforms.validators import DataRequired, EqualTo
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired

# Login imports
from werkzeug.security import generate_password_hash
from flask_login import UserMixin, current_user

# Config import
from baseconfig import app

db = SQLAlchemy(app)

# Models -----------------------------------------------------------------------------------
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150))
    password_hash = db.Column(db.String(150))
    role_id = db.Column(db.Integer, ForeignKey("user_level.role_id"), default=1)
    active_user = db.Column(db.Integer, default=1)  # 1 = Not registered, 2 = Activated user, 3 = "Deleted" user, admin has deactivated the account.


class User_level(db.Model):
    __tablename__ = "user_level"
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), nullable=False)

    def __init__(self, role_id, role_name):
        self.role_id = role_id
        self.role_name = role_name


class Comments(db.Model):
    __tablename__ = "comments"
    comment_id = db.Column(db.Integer, primary_key=True)
    f_id = db.Column(db.Integer, ForeignKey("file_structure.f_id"))
    user_id = db.Column(db.Integer, ForeignKey("user.id"))
    date = db.Column(db.DateTime, default=func.now())
    comment = db.Column(db.Text(1200), nullable=False)
    active_comment = db.Column(db.Boolean, default=True)

    def __init__(self, f_id, user_id, comment):
        self.f_id = f_id
        self.user_id = user_id
        self.comment = comment


class FileStructure(db.Model):
    __tablename__ = "file_structure"
    f_id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, ForeignKey("file_structure.f_id"), default=None)
    title = db.Column(db.String(50))
    description = db.Column(db.String(500))
    date = db.Column(db.DateTime, default=func.now())
    author = db.Column(db.Integer, ForeignKey("user.id"))
    access = db.Column(db.Integer, ForeignKey("user_level.role_id"))
    hits = db.Column(db.Integer, default=0)
    filename = db.Column(db.String(150))
    file_type = db.Column(db.Integer, ForeignKey("file_types.id"))

    def __init__(self, folder_id=None, title="", description="", author="", access=1, filename="", filetype=1):
        self.folder_id = folder_id
        self.title = title
        self.description = description
        self.author = author
        self.access = access
        self.filename = filename
        self.file_type = filetype


class FileTypes(db.Model):
    __tablename__ = "file_types"
    id = db.Column(db.Integer, primary_key=True)
    file_type = db.Column(db.String(50))

    def __init__(self, id, file_type):
        self.id = id
        self.file_type = file_type


class TagMap(db.Model):
    __tablename__ = "tag_map"
    id = db.Column(db.Integer, primary_key=True)
    f_id = db.Column(db.Integer, ForeignKey("file_structure.f_id"))
    tag_id = db.Column(db.Integer, ForeignKey("tags.id"))

    def __init__(self, f_id, tag_id):
        self.f_id = f_id
        self.tag_id = tag_id


class Tags(db.Model):
    __tablename__ = "tags"
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(50))

    def __init__(self, tag):
        self.tag = tag


class Log(db.Model):
    __tablename__ = "log"
    id = db.Column(db.Integer, primary_key=True)
    log_text = db.Column(db.String(1000))

    def __init__(self, log_text):
        self.log_text = log_text


# Forms -----------------------------------------------------------------------------------
class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()], render_kw={"autofocus": True, "placeholder": "Email"})
    password = PasswordField("Password", validators=[DataRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    name = StringField("Your name", validators=[DataRequired()], render_kw={"autofocus": True, "placeholder": "Your name"})
    email = EmailField("Your email", validators=[DataRequired()], render_kw={"placeholder": "Your email"})
    password = PasswordField("Password", validators=[DataRequired()], render_kw={"placeholder": "Password"})
    password_confirm = PasswordField(
        "Confirm password", validators=[DataRequired(), EqualTo("password", "Passwords must match")], render_kw={"placeholder": "Confirm password"}
    )
    submit = SubmitField("Sign up")


class UpdateUserForm(FlaskForm):
    name = StringField("Your name", validators=[DataRequired()], render_kw={"autofocus": False, "placeholder": "Your name"})
    password = PasswordField("Password", render_kw={"placeholder": "Password"})
    password_confirm = PasswordField("Confirm password", validators=[EqualTo("password", "Passwords must match")], render_kw={"placeholder": "Confirm password"})
    submit = SubmitField("Update")


class File(FlaskForm):
    title = StringField("Title", validators=[DataRequired()], render_kw={"autofocus": True, "placeholder": "Title"})
    description = TextAreaField("Description", render_kw={"placeholder": "Description"})
    file_url = FileField("File", validators=[FileRequired(), FileAllowed(["jpg", "jpeg", "png", "gif", "txt", "mp4", "mov", "docx", "pdf"])])
    tags = StringField("Tags", render_kw={"placeholder": "Tags"})
    access = RadioField(
        "access", choices=[("2", "Private"), ("1", "Public"), ("3", "Admin only")], validators=[DataRequired()], validate_choice=True, default="2", coerce=int
    )
    submit_file = SubmitField("Add File")


class Folder(FlaskForm):
    title = StringField("Folder name", validators=[DataRequired()], render_kw={"autofocus": True, "placeholder": "Folder name"})
    description = TextAreaField("Description", render_kw={"placeholder": "Description"})
    access = RadioField(
        "Private", choices=[("2", "Private"), ("1", "Public"), ("3", "Admin only")], validators=[DataRequired()], validate_choice=True, default="2", coerce=int
    )
    tags = StringField("Tags", render_kw={"placeholder": "Tags"})
    submit_folder = SubmitField("Add Folder")


class EditForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()], render_kw={"autofocus": True, "placeholder": "Title"})
    description = TextAreaField("Description", render_kw={"placeholder": "Description"})
    tags = StringField("Tags", render_kw={"placeholder": "Tags"})
    access = RadioField("access", choices=[("2", "Private"), ("1", "Public"), ("3", "Admin only")], validators=[DataRequired()], validate_choice=True, coerce=int)
    submit_editfile = SubmitField("Submit")


class CommentForm(FlaskForm):
    comment = TextAreaField("Comment", validators=[DataRequired()], render_kw={"autofocus": False, "placeholder": "What will we rant about today?"})
    submit_comment = SubmitField("Add Comment")


class SearchForm(FlaskForm):
    search = StringField("Search", validators=[DataRequired()], render_kw={"autofocus": False, "placeholder": "...enter search here!"})
    submit_search = SubmitField("Search")

class DeleteFileForm(FlaskForm):
    id = HiddenField("id")
    submit = SubmitField("Delete")

class DeleteCommentForm(FlaskForm):
    id = HiddenField("id")
    submit = SubmitField("Delete")

# Get the path you're currently at in all it's steps, gives quick access to folders further up.
class MasterPath:
    def __init__(self):
        self.__masterpath = [0]

    @property
    def masterpath(self):
        return self.__masterpath

    @masterpath.setter
    def masterpath(self, value):
        self.__masterpath = value

    def add(self, string):
        self.masterpath.append(string)

    def reset_path(self):
        self.masterpath = [0]

    def make_path(self, id):
        self.reset_path()
        stack = []
        while True:
            files = FileStructure.query.filter_by(f_id=id).first()
            db.session.commit()

            if files.folder_id == None:
                stack.append(files.f_id)
                break

            stack.append(files.f_id)
            id = files.folder_id

        for _ in range(len(stack)):
            self.add(stack.pop())

    def path_names(self):
        dic = {}
        files = FileStructure.query.all()
        db.session.commit()

        for x in files:
            if x.title != None:
                dic[x.f_id] = x.title
        return dic


def create_data():
    # Role_id
    user_level1 = User_level(1, "public")
    user_level2 = User_level(2, "user")
    user_level3 = User_level(3, "admin")
    db.session.add(user_level1)
    db.session.add(user_level2)
    db.session.add(user_level3)

    # File types
    folder = FileTypes(1, "Folder")
    jpg = FileTypes(2, "JPEG")
    png = FileTypes(3, "PNG")
    gif = FileTypes(4, "GIF")
    mp4 = FileTypes(5, "MP4")
    mov = FileTypes(6, "MOV")
    txt = FileTypes(7, "TXT")
    pdf = FileTypes(8, "PDF")
    any = FileTypes(100, "ANY")

    db.session.add(folder)
    db.session.add(jpg)
    db.session.add(gif)
    db.session.add(png)
    db.session.add(any)
    db.session.add(mp4)
    db.session.add(mov)
    db.session.add(txt)
    db.session.add(pdf)
    db.session.commit()

    # # Admin user
    admin = User(
        name="Admin",
        email="admin@admin.com",
        password_hash=generate_password_hash("Password1"),
        role_id=3,
        active_user=2,
    )
    db.session.add(admin)
    db.session.commit()
