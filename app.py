from functools import wraps
from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from data import articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

articles_var = articles()


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/articles')
def articles():
    cur = mysql.connection.cursor()

    results = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()

    if results > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = "No Articles Found"
        return render_template('articles.html', msg=msg)

    cur.close()


@app.route('/article/<string:id>/')
def article(id):
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    return render_template('article.html', article=article)


class RegisterForm(Form):
    name = StringField('Name', validators=[validators.Length(min=1, max=50)])
    username = StringField('Username', validators=[validators.Length(min=4, max=25)])
    email = StringField('Email', validators=[validators.Length(min=6, max=30)])
    password = PasswordField('Password', validators=[
                            validators.DataRequired(),
                            validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
        mysql.connection.commit()
        cursor.close()
        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cursor = mysql.connection.cursor()

        result = cursor.execute('SELECT * FROM users WHERE username = %s', [username])

        if result > 0:
            data = cursor.fetchone()
            password = data['password']

            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                app.logger.info('Password correct')
                return redirect(url_for('dashboard'))
            else:
                error = 'Password incorrect'
                app.logger.info(error)
                return render_template('login.html', error=error)
            cursor.close
        else:
            error = 'User not found'
            app.logger.info(error)
            return render_template('login.html', error=error)
    return render_template('login.html')


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@is_logged_in
def dashboard():
    cur = mysql.connection.cursor()

    results = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()

    if results > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = "No Articles Found"
        return render_template('dashboard.html', msg=msg)

    cur.close()


class ArticleForm(Form):
    title = StringField('Title', validators=[validators.Length(min=1, max=200)])
    body = TextAreaField('Body', validators=[validators.Length(min=30)])


@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)", (title, body, session['username']))

        mysql.connection.commit()
        cur.close()
        flash('Article created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_article.html', form=form)


@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    form = ArticleForm(request.form)
    form.title.data = article['title']
    form.body.data = article['body']
    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']

        cur = mysql.connection.cursor()
        cur.execute('UPDATE articles SET title=%s, body=%s WHERE id=%s', (title, body, id))

        mysql.connection.commit()
        cur.close()
        flash('Article updated', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_article.html', form=form)


@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM articles WHERE id = %s", [id])
    mysql.connection.commit()
    cur.close()
    flash('Article deleted', 'success')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
