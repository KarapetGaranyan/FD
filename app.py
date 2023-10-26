from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from webforms import UlForm, SearchForm, UserForm, LoginForm
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import os, shutil, ntpath, random, time, logging
from docxtpl import DocxTemplate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid as uuid
import os

BASE_PATH = os.getcwd()
TEMPLATES_FOLDER = f'{os.path.join(BASE_PATH, "")}templates_docs'
TREATIES_FOLDER = f'{os.path.join(BASE_PATH, "")}treaties'
UPLOAD_FOLDER = 'static/images/'

# Создание приложения Flask и секретного ключа
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fd.db'
app.config['SECRET_KEY'] = "123asd456qwe987"
db = SQLAlchemy(app)
migrate = Migrate(app, db) # render_as_batch=True
app.config['BASE_PATH'] = BASE_PATH
app.config['TEMPLATES_FOLDER'] = TEMPLATES_FOLDER
app.config['TREATIES_FOLDER'] = TREATIES_FOLDER
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/")
def index():
    return render_template("index.html")

# Create Admin Page
@app.route('/admin')
@login_required
def admin():
	id = current_user.id
	if id == 1:
		return render_template("admin.html")
	else:
		flash("Sorry you must be the Admin to access the Admin Page...")
		return redirect(url_for('dashboard'))

# Flask_Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))

# Create Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Succesfull!!")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password - Try Again!")
        else:
            flash("That User Doesn't Exist! Try Again...")
    return render_template('login.html', form=form)

# Create Logout Page
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash("You Have Been Logged Out!  Thanks For Stopping By...")
    return redirect(url_for('login'))

# Create Dashboard Page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.name_user_r = request.form['name_user_r']
        name_to_update.dolzhnost = request.form['dolzhnost']
        name_to_update.dolzhnost_r = request.form['dolzhnost_r']
        name_to_update.osnovanie = request.form['osnovanie']
        name_to_update.username = request.form['username']
        name_to_update.email = request.form['email']

        if request.files['profile_pic']:
            name_to_update.profile_pic = request.files['profile_pic']
            pic_filename = secure_filename(name_to_update.profile_pic.filename)
            pic_name = str(uuid.uuid1()) + "_" + pic_filename
            saver = request.files['profile_pic']
            name_to_update.profile_pic = pic_name
            try:
                db.session.commit()
                saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
                flash("Данные пользователя успешно обновлены!")
                return render_template("dashboard.html", form=form, name_to_update=name_to_update, id=id)
            except:
                flash("Ошибка! Попробуйте еще раз!")
                return render_template("dashboard.html", form=form, name_to_update=name_to_update, id=id)
        else:
            db.session.commit()
            flash("Данные пользователя успешно обновлены!")
            return render_template("dashboard.html", form=form, name_to_update=name_to_update, id=id)
    else:
        return render_template("dashboard.html", form=form, name_to_update=name_to_update, id=id)
    return render_template('dashboard.html')

@app.route('/rko', methods=['GET'])
def rko():
    key = int(request.args['id']) - 1
    try:
        shutil.rmtree(f'{app.config["TREATIES_FOLDER"]}', ignore_errors=False)
        os.mkdir("treaties")

        res = Uls.query.all()
        x = res[key].name
        hash = "%032x" % random.getrandbits(128)

        doc0 = DocxTemplate(TEMPLATES_FOLDER + "/Договоры.docx")
        context = {'Полное_наименование': x}
        doc0.render(context)
        doc0.save(TREATIES_FOLDER + "/Договоры.docx")

        shutil.make_archive(hash, "zip", app.config['TREATIES_FOLDER'])
        shutil.move(f'{app.config["BASE_PATH"]}/{hash}.zip', app.config['TREATIES_FOLDER'])
        session.clear()
        return send_file(f'{app.config["TREATIES_FOLDER"]}/{hash}.zip', as_attachment=True)
    except BaseException as e:
        logging.exception(e)
        return render_template("index.html", error=e)

@app.route('/uls')
def uls():
	uls = Uls.query.all()
	return render_template("uls.html", uls=uls)

@app.route('/uls/<int:id>')
def ul(id):
	ul = Uls.query.get_or_404(id)
	return render_template('ul.html', ul=ul)

# Регистрация ЮЛ
@app.route('/add-ul', methods=['GET', 'POST'])
@login_required
def add_ul():
    form = UlForm()
    if form.validate_on_submit():
        #poster = current_user.id
        poster = 1
        ul = Uls(name=form.name.data, name_sokr=form.name_sokr.data, inn=form.inn.data, ogrn=form.ogrn.data,
                 address=form.address.data, okpo=form.okpo.data, kpp=form.kpp.data, director=form.director.data,
                 director_r=form.director_r.data, dolzhnost=form.dolzhnost.data, dolzhnost_r=form.dolzhnost_r.data,
                 osnovanie=form.osnovanie.data, telephone=form.telephone.data, email=form.email.data, domen=form.domen.data,
                 nomer=form.nomer.data, poster_id=poster)
        form.name.data = ''
        form.name_sokr.data = ''
        form.inn.data = ''
        form.ogrn.data = ''
        form.address.data = ''
        form.kpp.data = ''
        form.okpo.data = ''
        form.director.data = ''
        form.director_r.data = ''
        form.dolzhnost.data = ''
        form.dolzhnost_r.data = ''
        form.osnovanie.data = ''
        form.telephone.data = ''
        form.email.data = ''
        form.domen.data = ''
        form.nomer.data = ''
        db.session.add(ul)
        db.session.commit()
        flash("Юр. лицо успешно зарегистрировано!")
    return render_template("add_ul.html", form=form)

# Обновление ЮЛ
@app.route('/uls/edit/<int:id>', methods=['GET', 'POST'])
def edit_ul(id):
    ul = Uls.query.get_or_404(id)
    form = UlForm()
    if form.validate_on_submit():
        ul.name = form.name.data
        ul.name_sokr = form.name_sokr.data
        ul.inn = form.inn.data
        ul.ogrn = form.ogrn.data
        ul.address = form.address.data
        ul.kpp = form.kpp.data
        ul.okpo = form.okpo.data
        ul.director = form.director.data
        ul.director_r = form.director_r.data
        ul.dolzhnost = form.dolzhnost.data
        ul.dolzhnost_r = form.dolzhnost_r.data
        ul.osnovanie = form.osnovanie.data
        ul.telephone = form.telephone.data
        ul.email = form.email.data
        ul.domen = form.domen.data
        ul.nomer = form.nomer.data
        ul.poster_id = form.poster_id.data
        db.session.add(ul)
        db.session.commit()
        flash("Данные по ЮЛ обновлены!")
        return redirect(url_for('ul', id=ul.id))
    if current_user.id == ul.poster_id or current_user == 1:
        form.name.data = ul.name
        form.name_sokr.data = ul.name_sokr
        form.inn.data = ul.inn
        form.ogrn.data = ul.ogrn
        form.address.data = ul.address
        form.kpp.data = ul.kpp
        form.okpo.data = ul.okpo
        form.director.data = ul.director
        form.director_r.data = ul.director_r
        form.dolzhnost.data = ul.dolzhnost
        form.dolzhnost_r.data = ul.dolzhnost_r
        form.osnovanie.data = ul.osnovanie
        form.telephone.data = ul.telephone
        form.email.data = ul.email
        form.domen.data = ul.domen
        form.nomer.data = ul.nomer
        form.poster_id.data = ul.poster_id
        return render_template('edit_ul.html', form=form)
    else:
        flash("You Aren't Authorized To Edit This Post...")
        uls = Uls.query.all()
        return render_template("uls.html", uls=uls)

# Удаление ЮЛ
@app.route('/uls/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_ul(id):
    ul_to_delete = Uls.query.get_or_404(id)
    id = current_user.id
    if id == ul_to_delete.poster.id or id == 1:
        try:
            db.session.delete(ul_to_delete)
            db.session.commit()
            flash("Данные по ЮЛ удалены!")
            uls = Uls.query.all()
            return render_template("uls.html", uls=uls)
        except:
            flash("Ошибка удаления данных по ЮЛ!")
            uls = Uls.query.all()
            return render_template("uls.html", uls=uls)
    else:
        flash("Вы не авторизованы для удаления данных")
        print(id)
        print(ul_to_delete.poster.id)
        uls = Uls.query.all()
        return render_template("uls.html", uls=uls)
# Поиск
@app.context_processor
def base():
	form = SearchForm()
	return dict(form=form)

@app.route('/search', methods=["POST"])
def search():
	form = SearchForm()
	uls = Uls.query
	if form.validate_on_submit():
		ul.searched = form.searched.data
		uls = uls.filter(Uls.inn.like('%' + ul.searched + '%'))
		uls = uls.order_by(Uls.name).all()
		return render_template("search.html", form=form,searched = ul.searched, uls = uls)

# Добавление пользователя
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
	name = None
	form = UserForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		if user is None:
			hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
			user = Users(name=form.name.data, name_user_r=form.name_user_r.data, dolzhnost=form.dolzhnost.data,
                         dolzhnost_r=form.dolzhnost_r.data, osnovanie=form.osnovanie.data, username=form.username.data,
                         email=form.email.data, password_hash=hashed_pw)
			db.session.add(user)
			db.session.commit()
		name = form.name.data
		form.name.data = ''
		form.name_user_r.data = ''
		form.dolzhnost.data = ''
		form.dolzhnost_r.data = ''
		form.osnovanie.data = ''
		form.username.data = ''
		form.email.data = ''
		form.password_hash.data = ''
		flash("Пользователь добавлен успешно!")
	our_users = Users.query.order_by(Users.date_added)
	return render_template("add_user.html", form=form,name=name,our_users=our_users)

# Обновление данных пользователя
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
	form = UserForm()
	name_to_update = Users.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.name = request.form['name']
		name_to_update.name_user_r = request.form['name_user_r']
		name_to_update.dolzhnost = request.form['dolzhnost']
		name_to_update.dolzhnost_r = request.form['dolzhnost_r']
		name_to_update.osnovanie = request.form['osnovanie']
		name_to_update.username = request.form['username']
		name_to_update.email = request.form['email'] 
		try:
			db.session.commit()
			flash("Данные пользователя успешно обновлены!")
			return render_template("update.html", form=form, name_to_update = name_to_update, id=id)
		except:
			flash("Ошибка! Попробуйте еще раз!")
			return render_template("update.html", form=form, name_to_update = name_to_update, id=id)
	else:
		return render_template("update.html", form=form, name_to_update = name_to_update, id = id)

# Удаление пользователя
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if id == current_user.id:
        user_to_delete = Users.query.get_or_404(id)
        name = None
        form = UserForm()
        try:
            db.session.delete(user_to_delete)
            db.session.commit()
            flash("Пользователь удален!!")
            our_users = Users.query.order_by(Users.date_added)
            return render_template("add_user.html", form=form,name=name,our_users=our_users)
        except:
            flash("Ой! Возникла ошибка при удалении пользователя, попробуйте еще раз...")
            return render_template("add_user.html", form=form, name=name,our_users=our_users)
    else:
        flash("Извините, вы не можете удалить этого пользователя! ")
        return redirect(url_for('dashboard'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500

# БАЗЫ ДАННЫХ
# Создание БД ЮЛ
class Uls(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    name_sokr = db.Column(db.String(255))
    inn = db.Column(db.String(255))
    ogrn = db.Column(db.String(255))
    address = db.Column(db.String(255))
    kpp = db.Column(db.String(255))
    okpo = db.Column(db.String(255))
    director = db.Column(db.String(255))
    director_r = db.Column(db.String(255))
    dolzhnost = db.Column(db.String(255))
    dolzhnost_r = db.Column(db.String(255))
    osnovanie = db.Column(db.String(255))
    telephone = db.Column(db.String(255))
    email = db.Column(db.String(255))
    domen = db.Column(db.String(255))
    nomer = db.Column(db.String(255))
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    name_user_r = db.Column(db.String(200), nullable=False)
    dolzhnost = db.Column(db.String(200), nullable=False)
    dolzhnost_r = db.Column(db.String(200), nullable=False)
    osnovanie = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(200), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(), nullable=True)
    password_hash = db.Column(db.String(128))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    uls = db.relationship('Uls', backref='poster')

if __name__ == "__main__":
    app.run(debug=True)
