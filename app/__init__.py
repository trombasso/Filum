# Flask
from flask import render_template, url_for, redirect, flash

# Database related imports
from sqlalchemy import update
from datetime import datetime

# Login imports
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid as uuid
from flask_login import login_user, LoginManager, login_required, logout_user, current_user

# Email confirmation systems
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from functools import wraps

# File management imports
import os

# Models
from models import User, User_level, Comments, FileStructure, FileTypes, TagMap, Tags, Log
from models import LoginForm, RegisterForm, File, Folder, EditForm, CommentForm, UpdateUserForm, SearchForm, DeleteCommentForm, DeleteFileForm
from models import MasterPath, app, db


# Login functionality
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login to access this feature"
login_manager.login_message_category = "error"  # Flash-message class


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


mail = Mail(app)


# Epost confirmation setup --------------------------------------------------------------
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
    except:
        return False
    return email


def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=app.config["MAIL_DEFAULT_SENDER"])
    mail.send(msg)


def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.active_user == 1:
            flash("Please confirm your account!", "error")
            return redirect(url_for("unconfirmed"))
        return func(*args, **kwargs)

    return decorated_function


# Finding the filetype of a file and returning the correct value to put in the Database.
def filetype_to_filetypeID(filename):
    ending = filename[-4:]
    if ending == ".jpg" or ending == "jpeg" or ending == ".JPG" or ending == "JPEG":
        return 2
    elif ending == ".png" or ending == ".PNG":
        return 3
    elif ending == ".gif" or ending == ".GIF":
        return 4
    elif ending == ".mp4" or ending == ".MP4":
        return 5
    elif ending == ".mov" or ending == ".MOV":
        return 6
    elif ending == ".txt" or ending == ".TXT":
        return 7
    elif ending == ".pdf" or ending == ".PDF":
        return 8
    else:
        return 100


# Tags -----------------------------------------------------------------------------------
def create_and_map_tags(f_id, tag_lis):
    existing_tags = Tags.query.all()
    lis_of_existing_tags = [x.tag.lower() for x in existing_tags]

    for elem in tag_lis:
        if elem.lower() not in lis_of_existing_tags:
            tag = Tags(tag=elem.lower())
            db.session.add(tag)
            db.session.commit()

            tag_map = TagMap(
                f_id=f_id,
                tag_id=tag.id,
            )
            db.session.add(tag_map)
            db.session.commit()

        else:
            for x in existing_tags:
                if x.tag.lower() == elem.lower():
                    tag_map = TagMap(f_id=f_id, tag_id=x.id)
                    db.session.add(tag_map)
                    db.session.commit()


# Log -----------------------------------------------------------------------------------
def logger(message: str):
    entry = Log(log_text=message)
    db.session.add(entry)
    db.session.commit()


# Search -----------------------------------------------------------------------------------
def search_func(key_word: str, access=1):
    lis = []

    lis.append(FileStructure.query.filter(FileStructure.title.contains(key_word)).all())
    lis.append(FileStructure.query.filter(FileStructure.description.contains(key_word)).all())
    lis.append(FileStructure.query.filter(FileStructure.date.contains(key_word)).all())

    tag_lis = Tags.query.filter(Tags.tag.contains(key_word)).all()
    lis_of_tag_ids = []
    for elm in tag_lis:
        lis_of_tag_ids.append(elm.id)

    lis.append(TagMap.query.filter(TagMap.tag_id.in_(lis_of_tag_ids)))

    lis_of_f_ids = []
    for i in lis:
        for j in i:
            lis_of_f_ids.append(j.f_id)

    temp_lis = []
    for i in lis_of_f_ids:  # To avoid dupelicates.
        if i not in temp_lis:
            temp_lis.append(i)

    files = FileStructure.query.filter(FileStructure.f_id.in_(temp_lis))
    return_lis = []
    for i in files:
        if i.access <= access:
            return_lis.append(i)

    return return_lis


# Routes -----------------------------------------------------------------------------------
@app.route("/", methods=["POST", "GET"])
def home():
    MasterPath.masterpath = [0]
    masterpath = MasterPath.masterpath
    file_form = File()
    folder_form = Folder()
    search_form = SearchForm()

    if current_user.is_authenticated and current_user.role_id == 3:
        files = FileStructure.query.filter_by(folder_id=None).order_by(FileStructure.file_type.asc())
    elif current_user.is_authenticated and current_user.role_id == 2:
        files = FileStructure.query.filter(FileStructure.access.in_([1, 2])).filter_by(folder_id=None).order_by(FileStructure.file_type.asc())
    else:
        files = FileStructure.query.filter_by(access=1, folder_id=None).order_by(FileStructure.file_type.asc())

    if folder_form.submit_folder.data and folder_form.validate() and current_user.role_id >= 2:
        folder = FileStructure(
            title=folder_form.title.data,
            description=folder_form.description.data,
            author=current_user.get_id(),
            access=folder_form.access.data,
            filename=None,
            filetype=1,
        )
        db.session.add(folder)
        db.session.commit()

        tag_lis = folder_form.tags.data.split(",")
        create_and_map_tags(folder.f_id, tag_lis)

        # Log
        logger(f"{datetime.now()}, Folder added. Info: \nUser: {current_user.get_id()}, Title: {folder.title}, Access: {folder.access}")

        flash("Folder created!", "success")
        return redirect(url_for("home"))

    if file_form.submit_file.data and file_form.validate() and current_user.role_id >= 2:
        file_name = secure_filename(file_form.file_url.data.filename)
        file_name = str(uuid.uuid1()) + "_" + file_name
        file_form.file_url.data.save(os.path.join(app.config["UPLOAD_FOLDER"], file_name))

        if current_user.get_id() == None:
            flash("Nei Jørgen, nei!", "error")
            return redirect(url_for("home"))

        file = FileStructure(
            title=file_form.title.data,
            description=file_form.description.data,
            author=current_user.get_id(),
            access=file_form.access.data,
            filename=file_name,
            filetype=filetype_to_filetypeID(file_name),
        )
        db.session.add(file)
        db.session.commit()

        tag_lis = file_form.tags.data.split(",")
        create_and_map_tags(file.f_id, tag_lis)

        # Log
        logger(
            f"{datetime.now()}, File added. Info: \nUser: {current_user.get_id()}, Title: {file.title}, Description: {file.description}, File name/path: {file.filename}, Access: {file.access}"
        )

        flash("File uploaded!", "success")
        return redirect(url_for("home"))

    if search_form.submit_search.data and search_form.validate():
        key_word = search_form.search.data
        return redirect(url_for("search", key_word=key_word))

    if current_user.is_authenticated and current_user.role_id == 3:
        file_form.access.choices = [("2", "Private"), ("1", "Public"), ("3", "Admin only")]
        file_form.process()

    elif current_user.is_authenticated and current_user.role_id == 2:
        file_form.access.choices = [("2", "Private"), ("1", "Public")]
        file_form.process()

    return render_template(
        "home.html",
        file_form=file_form,
        folder_form=folder_form,
        files=files,
        search_form=search_form,
        masterpath=masterpath,
    )


@app.route("/file/<int:id>", methods=["POST", "GET"])
def file(id):
    file_form = File()
    folder_form = Folder()
    comment_form = CommentForm()
    edit_form = EditForm()
    search_form = SearchForm()
    delete_comment_form = DeleteCommentForm()
    delete_file_form = DeleteFileForm()

    path = MasterPath()
    path.make_path(id)
    path_names = path.path_names()

    file_info = FileStructure.query.filter_by(f_id=id).first()
    file_info_description = file_info.description.split("\r\n")
    file_userinfo = User.query.filter_by(id=file_info.author).first()
    user_level = User_level.query.filter_by(role_id=file_info.access).first()
    filetype = FileTypes.query.filter_by(id=file_info.file_type).first()
    users = User.query.all()
    comments_temp = Comments.query.filter_by(f_id=id).order_by(Comments.date.asc())

    # kopierer comments-query til ny liste for å sørge for at selve kommentaren
    # blir riktig formatert
    comments = []
    for elem in comments_temp:
        comments.append(
            {
                "comment_id": elem.comment_id,
                "f_id": elem.f_id,
                "user_id": elem.user_id,
                "date": elem.date,
                "comment": elem.comment.split("\r\n"),
                "active_comment": elem.active_comment,
            }
        )

    # Query på bakgrunn av brukerrettigheter
    if current_user.is_authenticated and current_user.role_id == 3:
        files = FileStructure.query.filter_by(folder_id=id).order_by(FileStructure.file_type.asc())
    elif current_user.is_authenticated and current_user.role_id == 2:
        if current_user.role_id == 2 and file_info.access == 3:
            flash("Access not allowed", "error")
            if file_info.folder_id == None:
                return redirect(url_for("home"))
            return redirect(url_for("file", id=file_info.folder_id))
        else:
            files = FileStructure.query.filter_by(folder_id=id).order_by(FileStructure.file_type.asc())
    elif current_user.is_authenticated == False and file_info.access > 1:
        flash("Access not allowed!", "error")
        return redirect(url_for("login"))
    else:
        files = FileStructure.query.filter_by(access=1, folder_id=id).order_by(FileStructure.file_type.asc())

    # Ny Katalog
    if folder_form.submit_folder.data and folder_form.validate() and current_user.role_id >= 2:
        print(current_user.id, file_info.author)
        if current_user.id == file_info.author or current_user.role_id == 3:
            folder = FileStructure(
                folder_id=id,
                title=folder_form.title.data,
                description=folder_form.description.data,
                author=current_user.get_id(),
                access=folder_form.access.data,
                filename=None,
                filetype=1,
            )
            db.session.add(folder)
            db.session.commit()

            tag_lis = folder_form.tags.data.split(",")
            create_and_map_tags(folder.f_id, tag_lis)

            # Log
            logger(
                message=f"{datetime.now()}, Folder added. Info: \nUser: {current_user.get_id()}, Title: {folder.title}, Description: {folder.description}, Access: {folder.access}"
            )

            return redirect(url_for("file", id=id))
        else:
            flash("Access denied!!", "error")
            return redirect(url_for("file", id=id))

    # Ny Fil
    if file_form.submit_file.data and file_form.validate() and current_user.role_id >= 2:
        if current_user.id == file_info.author or current_user.role_id == 3:
            file_name = secure_filename(file_form.file_url.data.filename)
            file_name = str(uuid.uuid1()) + "_" + file_name
            file_form.file_url.data.save(os.path.join(app.config["UPLOAD_FOLDER"], file_name))

            file = FileStructure(
                folder_id=id,
                title=file_form.title.data,
                description=file_form.description.data,
                author=current_user.get_id(),
                access=file_form.access.data,
                filename=file_name,
                filetype=filetype_to_filetypeID(file_name),
            )
            db.session.add(file)
            db.session.commit()

            tag_lis = file_form.tags.data.split(",")
            create_and_map_tags(file.f_id, tag_lis)

            # Log
            logger(
                f"{datetime.now()}, File added. Info: \nUser: {current_user.get_id()}, Title: {file.title}, Description: {file.description}, File name/path: {file.filename}, Access: {file.access}"
            )

            flash("File uploaded!", "success")
            return redirect(url_for("file", id=id))
        else:
            flash("Access denied!", "error")
            return redirect(url_for("file", id=id))

    # Ny Kommentar
    if comment_form.submit_comment.data and comment_form.validate() and current_user.role_id >= 2:
        if current_user.role_id == 2 and current_user.active_user == 2 or current_user.role_id == 3:
            comment = Comments(
                f_id=id,
                user_id=current_user.get_id(),
                comment=comment_form.comment.data,
            )

            db.session.add(comment)
            db.session.commit()

            # Log
            logger(f"{datetime.now()}, Comment added. Info: \nUser: '{current_user.get_id()}', Comment: '{comment.comment}'")

            flash("Comment added!", "success")
            return redirect(url_for("file", id=id))
        else:
            flash("Access denied!", "error")
            return redirect(url_for("file", id=id))

    # Endre Fil/Katalog
    if edit_form.submit_editfile.data and edit_form.validate() and current_user.role_id >= 2:
        if current_user.id == file_info.author or current_user.role_id == 3:

            file_info.title = edit_form.title.data
            file_info.description = edit_form.description.data
            file_info.access = edit_form.access.data
            db.session.commit()

            TagMap.query.filter_by(f_id=id).delete()
            db.session.commit()
            tag_string = file_form.tags.data
            tag_lis = tag_string.split(",")
            existing_tags = Tags.query.all()
            lis_of_existing_tags = [x.tag.lower() for x in existing_tags]

            for elem in tag_lis:
                if elem.lower() not in lis_of_existing_tags:
                    tag = Tags(tag=elem.lower())
                    db.session.add(tag)
                    db.session.commit()

                    tag_map = TagMap(
                        f_id=file_info.f_id,
                        tag_id=tag.id,
                    )

                    db.session.add(tag_map)
                    db.session.commit()
                else:
                    for x in existing_tags:
                        if x.tag.lower() == elem.lower():
                            tag_map = TagMap(f_id=file_info.f_id, tag_id=x.id)

                            db.session.add(tag_map)
                            db.session.commit()

            tag_lis = file_form.tags.data.split(",")
            create_and_map_tags(file_info.f_id, tag_lis)

            # Log
            message = f"{datetime.now()}, File edited. Info: \nUser: {current_user.get_id()}, Title: {file_info.title}, Description: {file_info.description}, File name/path: {file_info.filename}, Access: {file_info.access}"
            logger(message)

            flash("Info updated. Good job!", "success")
            return redirect(url_for("file", id=id))

        else:
            flash("Access denied!", "error")
            return redirect(url_for("file", id=id))

    if search_form.submit_search.data and search_form.validate():
        key_word = search_form.search.data
        return redirect(url_for("search", key_word=key_word))

    # Hits
    statement = update(FileStructure).where(FileStructure.f_id == id).values(hits=file_info.hits + 1)
    db.session.execute(statement)
    db.session.commit()

    if current_user.is_authenticated and current_user.role_id == 3:
        lis = [("2", "Private"), ("1", "Public"), ("3", "Admin only")]
        file_form.access.choices = lis
        file_form.access.default = "2"
        file_form.process()
        folder_form.access.choices = lis
        folder_form.access.default = "2"
        folder_form.process()
        edit_form.access.choices = lis
        edit_form.access.default = "2"
        edit_form.process()
    elif current_user.is_authenticated and current_user.role_id == 2:
        lis = [("2", "Private"), ("1", "Public")]
        file_form.access.choices = lis
        file_form.access.default = "2"
        file_form.process()
        folder_form.access.choices = lis
        folder_form.access.default = "2"
        folder_form.process()
        edit_form.access.choices = lis
        edit_form.access.default = "2"
        edit_form.process()

    # Adding default values to EditForm
    tags = Tags.query.join(TagMap).filter(TagMap.f_id == id).all()
    tag_string = ""
    for tag in tags:
        tag_string += tag.tag
        if tags.index(tag) + 1 < len(tags):
            tag_string += ","

    edit_form.tags.data = tag_string
    edit_form.title.data = file_info.title
    edit_form.description.data = file_info.description
    edit_form.access.data = file_info.access

    return render_template(
        "file.html",
        file_form=file_form,
        folder_form=folder_form,
        files=files,
        masterpath=path.masterpath,
        path_names=path_names,
        file_info=file_info,
        file_userinfo=file_userinfo,
        user_level=user_level,
        file_type=filetype,
        comment_form=comment_form,
        comments=comments,
        users=users,
        edit_form=edit_form,
        file_info_description=file_info_description,
        tag=tag_string,
        search_form=search_form,
        delete_comment_form=delete_comment_form,
        delete_file_form=delete_file_form,
    )


@app.route("/delete", methods=["POST"])
@login_required
def delete():
    form = DeleteFileForm()
    f_id = form.id.data

    file = FileStructure.query.filter_by(f_id=f_id).first()
    files = FileStructure.query.all()

    if current_user.role_id == 3 or file.author == current_user.id:

        lis = []
        [lis.append("") for i in files if i.folder_id == f_id]

        if len(lis) > 0:  # Sanity check to see if there are files/folders in the folder you are trying to delete.
            flash("There is something in this folder! You cannot delete this folder.", "error")
            return redirect(url_for("file", id=f_id))

        if file.filename:
            file_path = app.config["UPLOAD_FOLDER"] + "/" + file.filename
            os.remove(file_path)  # Removing/deleting the file from 'static/uploaded_files'.

        # Log
        logger(
            f"{datetime.now()},File deleted. Info: \nUser: {current_user.get_id()}, Title: {file.title}, Description: {file.description}, File name/path: {file.filename}"
        )

        folder_id = file.folder_id # problem with delete, saving value before delete.
        # Delete from db
        Comments.query.filter_by(f_id=f_id).delete()
        TagMap.query.filter_by(f_id=f_id).delete()
        FileStructure.query.filter_by(f_id=f_id).delete()
        db.session.commit()
        
        if folder_id != None:  # Choosing correct route.
            return redirect(url_for("file", id=folder_id))
        return redirect(url_for("home"))

    flash("Not allowed! Nice Try!", "error")
    return redirect(url_for("home"))


@app.route("/delete_comment/<page>", methods=["POST"])
@login_required
def delete_comment(page):
    form = DeleteCommentForm()
    comment_id = form.id.data

    comment = Comments.query.filter_by(comment_id=comment_id).first()

    if comment.user_id == current_user.id or current_user.role_id == 3:
        comment.active_comment = False
        db.session.commit()
        # Log
        logger(f"{datetime.now()}, Comment deleted. Info: \nUser: {current_user.get_id()}, Comment: {comment.comment}")

        flash("Comment deleted!", "success")

        if page == "dashboard":
            return redirect(url_for("dashboard"))
        elif page == "file":
            return redirect(url_for("file", id=comment.f_id))

    flash("Not allowed!", "error")
    return redirect(url_for("home"))


@app.route("/search/<key_word>", methods=["GET", "POST"])
def search(key_word):
    search_form = SearchForm()

    if search_form.validate_on_submit():
        key_word = search_form.search.data
        return redirect(url_for("search", key_word=key_word))

    if current_user.is_authenticated:
        files = search_func(key_word, access=current_user.role_id)
    else:
        files = search_func(key_word)

    return render_template("search.html", files=files, search_form=search_form)


@app.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user.active_user == 3:
            return redirect(url_for("deactivated_user"))
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login successfull!", "success")
                return redirect(url_for("home"))

            else:
                flash("Wrong password! Please try again!", "error")
        else:
            flash("User does not exist. Are you registered?", "error")

    return render_template("login.html", form=form)


@app.route("/deactivated-user/")
def deactivated_user():
    return render_template("deactivated_user.html")


@app.route("/register/", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password.data, "sha256")
            user = User(name=form.name.data, email=form.email.data, password_hash=hashed_pw, role_id=2)
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully!", "success")

            token = generate_confirmation_token(user.email)
            confirm_url = url_for("confirm_email", token=token, _external=True)
            html = render_template("activate.html", confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(user.email, subject, html)

            login_user(user)
            flash("A confirmation email has been sent to you inbox!", "success")
            return redirect(url_for("unconfirmed"))

        else:
            flash("Email already exists!", "error")

    return render_template("register.html", form=form)


@app.route("/confirm/<token>")
@login_required
def confirm_email(token):
    try:
        emailconf = confirm_token(token)
    except:
        flash("The confirmation link is invalid or expired", "error")
    user = User.query.filter_by(email=emailconf).first_or_404()
    if user.active_user == 2:
        flash("Account allready confirmed. Please login", "success")
    else:
        user.active_user = 2
        db.session.add(user)
        db.session.commit()
        flash("You have confirmed your account. Good!", "success")
    return redirect(url_for("home"))


@app.route("/unconfirmed/")
@login_required
def unconfirmed():
    if current_user.active_user >= 2:
        return redirect("home")
    # flash("Please confirm your account!", "error")
    return render_template("unconfirmed.html")


@app.route("/resend")
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for("confirm_email", token=token, _external=True)
    html = render_template("activate.html", confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash("A new confirmation email has been sent.", "success")
    return redirect(url_for("unconfirmed"))


@app.route("/logout/")
@login_required
def logout():
    logout_user()
    flash("You have been successfully logged out!", "success")
    return redirect(url_for("login"))


@app.route("/dashboard/", methods=["GET", "POST"])
@login_required
@check_confirmed
def dashboard():
    form = UpdateUserForm()
    comment_form = DeleteCommentForm()
    file_types = FileTypes.query.all()
    all_files = FileStructure.query.with_entities(FileStructure.f_id, FileStructure.title)

    if form.validate_on_submit():
        if form.password.data == "":
            user = User.query.filter_by(id=current_user.id).first()
            user.name = form.name.data
            db.session.commit()
        else:
            user = User.query.filter_by(id=current_user.id).first()
            user.name = form.name.data
            user.password_hash = generate_password_hash(form.password.data, "sha256")
            db.session.commit()
        flash("Account updated", "success")
        return redirect(url_for("dashboard"))

    form.name.data = current_user.name

    if current_user.role_id == 3:
        files = FileStructure.query.filter_by(author=current_user.id)
        comments = Comments.query.all()
        users = User.query.all()
        log = Log.query.all()
        return render_template("dashboard.html", form=form, files=files, comments=comments, users=users, file_types=file_types, all_files=all_files, log=log, comment_form=comment_form)
    else:
        files = FileStructure.query.filter_by(author=current_user.id)
        comments = Comments.query.filter_by(user_id=current_user.id)
        return render_template("dashboard.html", form=form, files=files, comments=comments, file_types=file_types, all_files=all_files,comment_form=comment_form)


@app.route("/dashboard/activate-user/<int:user_id>/<int:active_user_toggle>")
@login_required
def active_user(user_id, active_user_toggle):
    user = User.query.filter_by(id=user_id).first()
    user.active_user = active_user_toggle

    db.session.commit()
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=False)
