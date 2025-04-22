from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for
import sqlite3
import redis
from flask_bcrypt import Bcrypt
from flasgger import Swagger

class Database:
    def __init__(self, db_name='usuarios.db'):
        self.db_name = db_name
        self.init_db()
    
    def get_connection(self):
        db = getattr(g, '_database', None)
        if db is None:
            db = g._database = sqlite3.connect(self.db_name)
            db.row_factory = sqlite3.Row
        return db
    
    def close_connection(self, exception):
        db = getattr(g, '_database', None)
        if db is not None:
            db.close()
    
    def init_db(self):
        with sqlite3.connect(self.db_name) as db:
            db.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
            """)
            db.commit()

class AuthService:
    def __init__(self, db, redis_client):
        self.db = db
        self.redis_client = redis_client
    
    def register(self, usuario, password):
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            db = self.db.get_connection()
            db.execute("INSERT INTO usuarios (usuario, password) VALUES (?, ?)", (usuario, hashed_password))
            db.commit()
            return {'message': 'Usuario registrado exitosamente'}, 201
        except sqlite3.IntegrityError:
            return {'error': 'El usuario ya existe'}, 400
    
    def login(self, usuario, password):
        db = self.db.get_connection()
        user = db.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
        if user and bcrypt.check_password_hash(user['password'], password):
            session['usuario'] = usuario
            self.redis_client.set(usuario, 'logged_in')
            return {'message': 'Inicio de sesión exitoso'}, 200
        else:
            return {'error': 'Credenciales inválidas'}, 401

    def logout(self):
        usuario = session.pop('usuario', None)
        if usuario:
            self.redis_client.delete(usuario)
        return {'message': 'Sesión cerrada'}, 200

app = Flask(__name__)
app.secret_key = 'supersecretkey'
Swagger(app)
bcrypt = Bcrypt(app)
database = Database()
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)
auth_service = AuthService(database, redis_client)

@app.teardown_appcontext
def close_connection(exception):
    database.close_connection(exception)

@app.route('/')
def home():
    if 'usuario' in session:
        return f'Bienvenido {session["usuario"]} | <a href="/logout">Cerrar sesión</a>'
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']
        response, status = auth_service.register(usuario, password)
        return jsonify(response), status
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']
        response, status = auth_service.login(usuario, password)
        return jsonify(response), status
    return render_template('login.html')

@app.route('/logout')
def logout():
    response, status = auth_service.logout()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)

