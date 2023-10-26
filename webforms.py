from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField,PasswordField,BooleanField,SelectField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_wtf.file import FileField

class UlForm(FlaskForm):
    name = StringField("Полное наименование", validators=[DataRequired()])
    name_sokr = StringField("Сокращенное наименование", validators=[DataRequired()])
    inn = StringField("ИНН", validators=[DataRequired()])
    ogrn = StringField("ОГРН", validators=[DataRequired()])
    address = StringField("Адрес", validators=[DataRequired()])
    kpp = StringField("КПП", validators=[DataRequired()])
    okpo = StringField("ОКПО", validators=[DataRequired()])
    director = StringField("ФИО Директора", validators=[DataRequired()])
    director_r = StringField("ФИО Директора в родительном падеже", validators=[DataRequired()])
    dolzhnost = StringField("Должность", validators=[DataRequired()])
    dolzhnost_r = StringField("Должность в родительном падеже", validators=[DataRequired()])
    osnovanie = StringField("Устава/Доверенности №_________ от __.__.____г.", validators=[DataRequired()])
    telephone = StringField("Телефон", validators=[DataRequired()])
    email = StringField("Электронная почта", validators=[DataRequired()])
    domen = StringField("Сайт")
    nomer = StringField("Номер договора", validators=[DataRequired()])
    poster_id = SelectField(u'Выбрать подписанта', choices=[('1', 'Иванов Иван Иванович'), ('2', 'Петров Петр Петрович')])
    submit = SubmitField("Отправить")

class SearchForm(FlaskForm):
	searched = StringField("Searched", validators=[DataRequired()])
	submit = SubmitField("Submit")

class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

class UserForm(FlaskForm):
    name = StringField("ФИО сотрудника", validators=[DataRequired()])
    name_user_r = StringField("ФИО сотрудника в родительном падеже", validators=[DataRequired()])
    dolzhnost = StringField("Должность", validators=[DataRequired()])
    dolzhnost_r = StringField("Должность в родительном падеже", validators=[DataRequired()])
    osnovanie = StringField("Дата и номер доверенности по формату:  № __________ от __.__.____г.", validators=[DataRequired()])
    username = StringField("Имя пользователя", validators=[DataRequired()])
    email = StringField("Электронная почта", validators=[DataRequired()])
    password_hash = PasswordField('Пароль', validators=[DataRequired(),EqualTo('password_hash2', message='Пароли должны совпадать!')])
    password_hash2 = PasswordField('Подтверждение пароля', validators=[DataRequired()])
    profile_pic = FileField("Profile Pic")
    submit = SubmitField("Отправить")