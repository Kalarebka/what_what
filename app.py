from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm, RecaptchaField
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import (
	StringField,
	TextAreaField,
	SubmitField,
	PasswordField,
	DateField,
	SelectField
)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
db = SQLAlchemy(app)

app.secret_key = 'super secret key'

# Login manager

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String, unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


# Run only once, to create the database
#db.create_all()





@app.route('/', methods=["GET", "POST"])
def index():
	return render_template("index.html")


# Logowanie
@app.route('/login', methods=["GET", "POST"])
def login():
	return 'login'

# Rejestracja
@app.route('/signup', methods=["GET", "POST"])
def signup():
	form = SignupForm()
	if request.method == "POST":
		if form.validate_on_submit():
			# Read data from the form
			login = form.user.data
			password = form.password.data
			email = form.email.data

			# Check if email and login do not exist in database
			if User.query.filter_by(email=email).first():
				flash("User with this email already exists.")
				return redirect(url_for('signup'))
			if User.query.filter_by(login=login).first():
				flash("Name already taken.")
				return redirect(url_for('signup'))

			# Create new user and save to database
			new_user = User(email=email,
							password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8),
							login=login)
			db.session.add(new_user)
			db.session.commit()
			#Log in and authenticate user
			login_user(new_user)
			return redirect(url_for('signup_success'))	
	
	return render_template("signup.html", form=form)

@app.route('/logout', methods=["GET", "POST"])
def logout():
	return 'logout'

@app.route('/signup_success', methods=["GET", "POST"])
def signup_success():
	return render_template("signup_success.html")


@app.route('/ask_question', methods=["GET", "POST"])
def question():
	return "question"


@app.route('/answer', methods=["GET", "POST"])
def answer():
	return "answer"


@app.route('/', methods=["GET", "POST"])
def list_of_questions():
	return "list of questions"


@app.route('/', methods=["GET", "POST"])
def show_random_answer():
	return "random answer"


@app.route('/', methods=["GET", "POST"])
def show_list_of_answers():
	return "list of answers"


class SignupForm(FlaskForm):
	user = StringField('Login')
	password = PasswordField('Password')
	confirm_password = PasswordField('Repeat Password')
	email = StringField('Email')
	#recaptcha = RecaptchaField()
	submit = SubmitField('Submit')

	#password = PasswordField('New Password', [
	#        validators.DataRequired(),
	#        validators.EqualTo('confirm', message='Passwords must match')
	#])






if __name__ == "__main__":
	app.run(host='0.0.0.0', debug=True)
