import datetime
import re
from functools import wraps

import mysql.connector as connector
from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

from mysqldb import DBConnector

app = Flask(__name__)
application = app
app.config.from_pyfile('config.py')

db_connector = DBConnector(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'
login_manager.login_message_category = 'warning'


def db_operation(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time, end_time = None, None
        connection = db_connector.connect()
        try:
            start_time = datetime.datetime.now()
            with connection.cursor(named_tuple=True, buffered=True) as cursor:
                result = func(cursor, *args, **kwargs)
                connection.commit()
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            end_time = datetime.datetime.now()
            print(f"Duration {func}: {end_time - start_time}")
            # connection.close()
        return result

    return wrapper


class User(UserMixin):
    def __init__(self, user_id, user_login):
        self.id = user_id
        self.user_login = user_login


def get_roles(cursor):
    cursor.execute("SELECT * FROM roles")
    return cursor.fetchall()


@login_manager.user_loader
def load_user(user_id):
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute("SELECT id, login FROM users WHERE id = %s;", (user_id,))
        user = cursor.fetchone()
    if user is not None:
        return User(user.id, user.login)
    return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')


@app.route('/auth', methods=['POST', 'GET'])
@db_operation
def auth(cursor):
    if request.method == 'POST':
        login = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember_me', None) == 'on'

        cursor.execute(
            "SELECT id, login FROM users WHERE login = %s AND password_hash = SHA2(%s, 256)",
            (login, password)
        )
        user = cursor.fetchone()

        if user:
            flash('Авторизация прошла успешно', 'success')
            login_user(User(user.id, user.login), remember=remember_me)
            next_url = request.args.get('next', url_for('index'))
            return redirect(next_url)
        flash('Invalid username or password', 'danger')
    return render_template('auth.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/counter')
def counter():
    session['counter'] = session.get('counter', 0) + 1
    return render_template('counter.html')


@app.route('/users')
@db_operation
def users(cursor):
    cursor.execute("SELECT users.*, roles.name AS role FROM users LEFT JOIN roles ON users.role_id = roles.id")
    users = cursor.fetchall()
    return render_template('users.html', users=users)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@db_operation
def users_delete(cursor, user_id):
    query = "DELETE FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    flash('Учетная запись успешно удалена', 'success')
    return redirect(url_for('users'))

def validate_first_name(first_name):
    errors = ""
    try:
        if not first_name:
            raise ValueError("Имя не может быть пустым.")
        if not re.match(r'^[a-zA-Zа-яА-ЯёЁ]+$', first_name):
            raise ValueError("Имя должно содержать только буквы.")
    except Exception as e:
        errors = e

    return errors


def validate_last_name(last_name):
    errors = ""
    try:
        if not last_name:
            raise ValueError("Фамилия не может быть пустой.")
        if not re.match(r'^[a-zA-Zа-яА-ЯёЁ]+$', last_name):
            raise ValueError("Фамилия должна содержать только буквы.")
    except Exception as e:
        errors = e

    return errors


def validate_login(login):
    errors = ""
    try:
        if not login:
            raise ValueError("Логин не может быть пустым.")
        if len(login) < 5:
            raise ValueError("Логин должен быть не менее 5 символов.")
        if not login or not re.match(r'^[a-zA-Z0-9]+$', login):
            raise ValueError("Логин должен состоять только из латинских букв и цифр.")

    except Exception as e:
        errors = e

    return errors


def validate_password(password):
    errors = ""
    try:
        if not password:
            raise ValueError("Пароль не может быть пустым.")
        if len(password) < 8:
            raise ValueError("Пароль должен содержать не менее 8 символов")
        if len(password) > 128:
            raise ValueError("Пароль должен содержать не более 128 символов")
        if not re.search(r'[a-z]', password):
            raise ValueError("Пароль должен содержать как минимум одну строчную букву")
        if not re.search(r'[A-Z]', password):
            raise ValueError("Пароль должен содержать как минимум одну заглавную букву")
        if not re.search(r'\d', password):
            raise ValueError("Пароль должен содержать как минимум одну цифру")
        if not re.match(r'^[a-zA-Zа-яА-Я0-9~!@#$%^&*_+()[\]{}<>\\/|"\'.,:;]*$', password):
            raise ValueError(
                "Пароль должен состоять только из латинских или кириллических букв, арабских цифр и допустимых символов")
        if ' ' in password:
            raise ValueError("Пароль не должен содержать пробелов")

    except Exception as e:
        errors = e

    return errors

@app.route('/users/new', methods=['POST', 'GET'])
@login_required
@db_operation
def users_new(cursor):
    user_data = {}
    errors = {}
    if request.method == 'POST':
        fields = ('login', 'password', 'first_name', 'middle_name', 'last_name', 'role_id')
        user_data = {field: request.form[field] or None for field in fields}
        errors['login'] = validate_login(user_data['login'])
        errors['password'] = validate_password(user_data['password'])
        errors['first_name'] = validate_first_name(user_data['first_name'])
        errors['last_name'] = validate_last_name(user_data['last_name'])

        if errors['login'] or errors['password'] or errors['first_name'] or errors['last_name']:
            return render_template(
                'users_new.html',
                user_data=user_data,
                roles=get_roles(cursor),
                errors=errors
            )

        try:
            query = (
                "INSERT INTO users (login, password_hash, first_name, middle_name, last_name, role_id) VALUES "
                "(%(login)s, SHA2(%(password)s, 256), %(first_name)s, %(middle_name)s, %(last_name)s, %(role_id)s)"
            )
            cursor.execute(query, user_data)
            flash('Учетная запись успешно создана', 'success')
            return redirect(url_for('users'))
        except connector.errors.DatabaseError:
            flash('Произошла ошибка при создании записи. Проверьте, что все необходимые поля заполнены', 'danger')
    return render_template('users_new.html', user_data=user_data, roles=get_roles(cursor), errors={})


@app.route('/users/<int:user_id>/view')
@db_operation
def users_view(cursor, user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, [user_id])
    user_data = cursor.fetchone()
    if not user_data:
        flash('Пользователя нет в базе данных', 'danger')
        return redirect(url_for('users'))
    query = "SELECT name FROM roles WHERE id = %s"
    cursor.execute(query, [user_data.role_id])
    user_role = cursor.fetchone()
    return render_template('users_view.html', user_data=user_data, user_role=user_role.name)


@app.route('/users/<int:user_id>/edit', methods=['POST', 'GET'])
@login_required
@db_operation
def users_edit(cursor, user_id):
    query = ("SELECT first_name, middle_name, last_name, role_id "
             "FROM users WHERE id = %s")
    cursor.execute(query, [user_id])
    user_data = cursor.fetchone()
    if not user_data:
        flash('Пользователя нет в базе данных', 'danger')
        return redirect(url_for('users'))
    if request.method == 'POST':
        fields = ('first_name', 'middle_name', 'last_name', 'role_id')
        user_data = {field: request.form[field] or None for field in fields}
        user_data['id'] = user_id
        try:
            query = ("UPDATE users SET first_name = %(first_name)s, "
                     "middle_name = %(middle_name)s, last_name = %(last_name)s, "
                     "role_id = %(role_id)s WHERE id = %(id)s")
            cursor.execute(query, user_data)
            flash('Учетная запись успешно изменена', 'success')
            return redirect(url_for('users'))
        except connector.errors.DatabaseError:
            flash('Произошла ошибка при изменении записи.', 'danger')
    return render_template('users_edit.html', user_data=user_data, roles=get_roles(cursor))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
@db_operation
def change_password(cursor):
    errors = {}
    if request.method == 'POST':
        user_id = current_user.id
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if confirm_password != new_password:
            errors['confirm_password'] = "Пароли должны совпадать"

        cursor.execute("SELECT id FROM users WHERE id = %s AND password_hash = SHA2(%s, 256)", (user_id, old_password))

        if not cursor.fetchone():
            errors['old_password'] = "Введён неверный пароль"

        errors['new_password'] = validate_password(new_password)

        if not errors['new_password'] and not errors['new_password']:
            cursor.execute("UPDATE users SET password_hash = SHA2(%s, 256) WHERE id = %s", (new_password, user_id))
            flash("Вы успешно сменили пароль", "susses")
            return redirect(url_for('users'))

    return render_template('change_password.html', errors=errors)

if __name__=='__main__':
    app.run(debug=True)