from flask import Flask
import configparser

config_file = configparser.ConfigParser()
# config_file.read("/var/www/config_filum.ini")
config_file.read("config_local.ini")
config_file.sections()


username = config_file["SETTINGS"]["username"]
password = config_file["SETTINGS"]["password"]
host = config_file["DATABASE"]["host"]
db_name = config_file["DATABASE"]["db_name"]

app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = config_file["FILES"]["upload_folder"]
app.config["SECRET_KEY"] = config_file["SECRET"]["secret_key"]
app.config["SECURITY_PASSWORD_SALT"] = config_file["SECRET"]["security_password_salt"]
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://" + username + ":" + password + "@" + host + "/" + db_name

# Mail Settings
app.config["MAIL_PORT"] = config_file["MAIL"]["mail_port"]
app.config["MAIL_SERVER"] = config_file["MAIL"]["mail_server"]
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = config_file["MAIL"]["mail_username"]
app.config["MAIL_PASSWORD"] = config_file["MAIL"]["mail_password"]
app.config["MAIL_DEFAULT_SENDER"] = config_file["MAIL"]["mail_default_sender"]
