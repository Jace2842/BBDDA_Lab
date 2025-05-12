import base64
import logging
from time import time
from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for, send_file, make_response,Response
import sqlite3
from flask_bcrypt import Bcrypt
from flasgger import Swagger
import psycopg2
from datetime import datetime
from config import load_config
import hashlib
from sqlalchemy import extract, func
import io
from tkinter import Tk, filedialog
import pandas as pd
import pdfkit
from psycopg2.extras import RealDictCursor
import json
from flask_session import Session
import redis
from elasticsearch import Elasticsearch
import uuid
from threading import Thread
import queue
import pickle

# Configuración de logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                   filename='app.log')
logger = logging.getLogger(__name__)


db_config = load_config()
log_queue = queue.Queue()
app = Flask(__name__)
app.secret_key = 'supersecretkey'
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)
# Configuración de Elasticsearch
es = Elasticsearch("http://localhost:9200")
INDEX_LOGS = "logs_usuarios"


# --- Middleware Flask para capturar logs de actividad ---
@app.before_request
def before_request():
    g.inicio = time()

@app.after_request
def after_request(response):
    duracion = int((time() - g.inicio) * 1000)  # Duración en milisegundos
    usuario_id = request.headers.get("X-User-ID", "anonimo")
    sesion_id = request.headers.get("X-Session-ID", str(uuid.uuid4()))
    
    # Recuperar datos adicionales del usuario desde la base de datos
    usuario_data = obtener_datos_usuario(usuario_id)

    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": usuario_id,
        "sesion_id": sesion_id,
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        "tiempo_respuesta_ms": duracion,
        "usuario_data": usuario_data  # Aquí añadimos los datos adicionales
    }
    log_queue.put(log)  # Enviar el log a la cola
    return response

def obtener_datos_usuario(usuario_id):
    """
    Función que obtiene datos adicionales de un usuario desde la base de datos.
    """
    try:
        with psycopg2.connect(**db_config) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT nombre, direccion, saldo FROM usuarios WHERE id = %s", (usuario_id,))
                result = cur.fetchone()
                if result:
                    return {
                        "nombre": result[0],
                        "direccion": result[1],
                        "saldo": result[2]
                    }
                else:
                    return {"error": "Usuario no encontrado"}
    except Exception as e:
        print(f"Error al obtener datos de usuario: {e}")
        return {"error": str(e)}

# --- Endpoint API para consultar datos de logs ---
@app.route("/api/datos", methods=["GET"])
def consultar_datos():
    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
    }
    return log_data


try:
    redis_client.ping()
except redis.exceptions.ConnectionError:
    redis_client = None
    print("Redis no disponible. Se desactivará caché de sesiones.")

if redis_client:
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis_client

Session(app)
Swagger(app)
bcrypt = Bcrypt(app)

#SQLite para persistencia local de usuarios
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

#seguridad con SQLite y sesión en Redis
class AuthService:
    def __init__(self, db):
        self.db = db

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
            return {'message': 'Inicio de sesión exitoso'}, 200
        else:
            return {'error': 'Credenciales inválidas'}, 401

    def logout(self):
        session.pop('usuario', None)
        return {'message': 'Sesión cerrada'}, 200

database = Database()
auth_service = AuthService(database)

@app.teardown_appcontext
def close_connection(exception):
    database.close_connection(exception)

@app.route('/')
def home():
    if 'usuario' in session:
        return f'Bienvenido {session["usuario"]} | <a href="/logout">Cerrar sesión</a>'
    return render_template('home.html')

@app.route('/test')
def test():
    if 'usuario' in session:
     return render_template('test.html')
    return f'Bienvenido {session["usuario"]} | <a href="/logout">Cerrar sesión</a>'


@app.route('/mapa')
def mapa():
    if 'usuario' in session:
     return render_template('mapa.html')
    return f'Bienvenido {session["usuario"]} | <a href="/logout">Cerrar sesión</a>'



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
        if status == 200:
            return redirect(url_for('menu'))
        else:
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/menu')
def menu():
    if 'usuario' not in session:
        return redirect(url_for('home'))
    return render_template('menu.html')

@app.route('/logout')
def logout():
    auth_service.logout()
    return redirect(url_for('home'))


def validar_contraseña(cur, alumno_id, password):
    cur.execute("SELECT hash_password FROM alumn WHERE id = %s", (alumno_id,))
    result = cur.fetchone()
    if not result:
        return False, "Alumno no encontrado"

    stored_hash = result[0]
    password_hash = hashlib.md5(password.encode()).hexdigest()
    return (password_hash == stored_hash), "Contraseña incorrecta" if password_hash != stored_hash else None

@app.route('/alumnos_url', methods=['GET', 'POST'])
def alumnos():
    config = load_config()

    
    if request.method == 'POST' and request.is_json:
        alumno_id = request.json.get("id_alumno")
        password = request.json.get("nota_password")
        if not alumno_id or not password:
            return jsonify({"error": "Faltan datos"}), 400

        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                valido, mensaje = validar_contraseña(cur, alumno_id, password)
                if not valido:
                    return jsonify({"error": mensaje}), 403

                cur.execute("SELECT pgp_sym_decrypt(nota::bytea, %s) FROM alumn WHERE id = %s", (password, alumno_id))
                nota_descifrada = cur.fetchone()[0]
                return jsonify({"nota": nota_descifrada}), 200

    
    search_params = {key: request.args.get(key, '') for key in [
        'search_nombre', 'search_apellido', 'search_direccion', 
        'search_saldo', 'search_fecha_inicio', 'search_fecha_fin', 
        'search_birthday_inicio', 'search_birthday_fin'
    ]}

    cache_key = f"alumnos_cache:{json.dumps(search_params, sort_keys=True)}"
    cache_data = None

    if redis_client:
        try:
            raw_data = redis_client.get(cache_key)
            if raw_data:
                cache_data = json.loads(raw_data.decode('utf-8'))
                return render_template('menu.html', **cache_data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            redis_client.delete(cache_key)
            print("Caché inválida eliminada:", cache_key)

    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit

    alumnos_dict = []
    total_alumnos = 0
    has_next = False

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                query_conditions = []
                query_params = []

                if search_params['search_nombre']:
                    query_conditions.append("first_name ILIKE %s")
                    query_params.append(f"%{search_params['search_nombre']}%")
                if search_params['search_apellido']:
                    query_conditions.append("last_name ILIKE %s")
                    query_params.append(f"%{search_params['search_apellido']}%")
                if search_params['search_direccion']:
                    query_conditions.append("street_address ILIKE %s")
                    query_params.append(f"%{search_params['search_direccion']}%")
                if search_params['search_saldo']:
                    query_conditions.append("saldo = %s")
                    query_params.append(search_params['search_saldo'])
                if search_params['search_birthday_inicio'] and search_params['search_birthday_fin']:
                    query_conditions.append("birthday BETWEEN %s AND %s")
                    query_params.extend([search_params['search_birthday_inicio'], search_params['search_birthday_fin']])
                if search_params['search_fecha_inicio'] and search_params['search_fecha_fin']:
                    query_conditions.append("lastmodified BETWEEN %s AND %s")
                    query_params.extend([search_params['search_fecha_inicio'], search_params['search_fecha_fin']])

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                cur.execute(f'''
                    SELECT id, first_name, last_name, street_address, 
                           TO_CHAR(birthday, 'YYYY-MM-DD'), TO_CHAR(lastmodified, 'YYYY-MM-DD HH24:MI:SS'), saldo
                    FROM alumn
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT %s OFFSET %s;
                ''', tuple(query_params + [limit, offset]))
                rows = cur.fetchall()

                cur.execute(f"SELECT COUNT(*) FROM alumn WHERE {where_clause};", tuple(query_params))
                total_alumnos = cur.fetchone()[0]

                for row in rows:
                    alumnos_dict.append({
                        "id": row[0],
                        "first_name": row[1],
                        "last_name": row[2],
                        "street_address": row[3],
                        "birthday": row[4],
                        "lastmodified": row[5],
                        "saldo": float(row[6]),
                        "nota": "********"
                    })
                has_next = len(alumnos_dict) == limit

    except Exception as e:
        print("Error:", e)

    render_data = {
        "alumnos_data": alumnos_dict,
        "page": page,
        "has_next": has_next,
        "total_alumnos": total_alumnos,
        **search_params
    }

    if redis_client:
        try:
            redis_client.setex(cache_key, 300, json.dumps(render_data))
        except Exception as e:
            print("Error guardando caché en Redis:", e)

    return render_template('menu.html', **render_data)

@app.route('/profesores_url')
def profesores():
    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit

    search_id = request.args.get('search_id', '')
    search_nombre = request.args.get('search_nombre', '')
    search_fecha_inicio = request.args.get('search_fecha_inicio', '')
    search_fecha_fin = request.args.get('search_fecha_fin', '')

    config = load_config()

    profesores_dict = []
    total_profesores = 0
    has_next = False

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                query_conditions = []
                query_params = []

                if search_id:
                    query_conditions.append("id = %s")
                    query_params.append(search_id)
                if search_nombre:
                    query_conditions.append("name ILIKE %s")
                    query_params.append(f"%{search_nombre}%")
                if search_fecha_inicio and search_fecha_fin:
                    query_conditions.append("lastmodified BETWEEN %s AND %s")
                    query_params.extend([search_fecha_inicio, search_fecha_fin])

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                query = f"""
                    SELECT id, name, lastmodified, nota
                    FROM teacher
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT %s OFFSET %s;
                """
                query_params.extend([limit, offset])
                cur.execute(query, tuple(query_params))
                rows = cur.fetchall()

                count_query = f"SELECT COUNT(*) FROM teacher WHERE {where_clause};"
                cur.execute(count_query, tuple(query_params[:-2]))  # sin paginación
                total_profesores = cur.fetchone()[0]

                for u in rows:
                    profesores_dict.append({
                        "id": u[0],
                        "name": u[1],
                        "lastmodified": u[2],
                        "nota": u[3]
                    })
                has_next = len(profesores_dict) == limit

    except (Exception, psycopg2.DatabaseError) as error:
        print("Error:", error)

    return render_template('menu.html',
                           profesores_data=profesores_dict,
                           page=page,
                           has_next=has_next,
                           total_profesores=total_profesores,
                           search_id=search_id,
                           search_nombre=search_nombre,
                           search_fecha_inicio=search_fecha_inicio,
                           search_fecha_fin=search_fecha_fin)

@app.route('/matriculados_url')
def matriculados():
    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit
    search_alumn_id = request.args.get('search_alumn_id', '').strip()
    search_course_id = request.args.get('search_course_id', '').strip()
    search_lastmodified = request.args.get('search_lastmodified', '').strip()
    search_calificacion = request.args.get('search_calificacion', '').strip()

    config = load_config()
    matriculados_dict = []
    total_matriculados = 0

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                # Construcción dinámica de condiciones
                query_conditions = []
                query_params = []

                if search_alumn_id:
                    query_conditions.append("course_alumn_rel.alumn_id = %s")
                    query_params.append(search_alumn_id)

                if search_course_id:
                    query_conditions.append("course_alumn_rel.course_id = %s")
                    query_params.append(search_course_id)

                if search_lastmodified:
                    query_conditions.append("course_alumn_rel.lastmodified::text ILIKE %s")
                    query_params.append(f"%{search_lastmodified}%")
                
                if search_calificacion:
                    query_conditions.append("course_alumn_rel.calificacion = %s")
                    query_params.append(f"%{search_calificacion}%")

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                # Consulta SQL con JOIN para obtener el nombre del profesor
                query = f"""
                    SELECT course_alumn_rel.alumn_id, course_alumn_rel.course_id, course_alumn_rel.lastmodified, course_alumn_rel.calificacion
                    FROM course_alumn_rel
                    WHERE {where_clause}
                    ORDER BY course_alumn_rel.alumn_id
                    LIMIT %s OFFSET %s;
                """
                query_params.extend([limit, offset])

                # Ejecutar consulta principal
                cur.execute(query, tuple(query_params))
                rows = cur.fetchall()

                # Contar el total de registros con los filtros aplicados
                count_query = f"SELECT COUNT(*) FROM course_alumn_rel WHERE {where_clause};"
                cur.execute(count_query, tuple(query_params[:-2]))  # Sin los parámetros de paginación
                total_matriculados = cur.fetchone()[0]

                # Convertir resultados en diccionario
                matriculados_dict = [
                    {
                        "alumn_id": row[0],
                        "course_id": row[1],
                        "lastmodified": row[2],
                        "calificacion": row[3],
                    }
                    for row in rows
                ]

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error al obtener matriculados: {error}")

    has_next = len(matriculados_dict) == limit

    return render_template(
        'menu.html',
        matriculados_data=matriculados_dict,  
        page=page,
        has_next=has_next,
        total_matriculados=total_matriculados,
        search_alumn_id=search_alumn_id,
        search_course_id=search_course_id,
        search_lastmodified=search_lastmodified,
        search_calificacion=search_calificacion,
    )


@app.route('/clases_url')
def clases():
    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit

    search_nombre = request.args.get('search_nombre', '')
    search_teacher_name = request.args.get('search_teacher_name', '')
    search_precio = request.args.get('search_precio', '')
    search_cupo_disponible = request.args.get('search_cupo_disponible', '')
    search_nombre2 = request.args.get('search_nombre2', 'esp')

    config = load_config()
    course_dict = []
    total_cursos = 0

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                query_conditions = []
                query_params = []

                if search_nombre:
                    query_conditions.append("course.name ILIKE %s")
                    query_params.append(f"%{search_nombre}%")
                if search_teacher_name:
                    query_conditions.append("teacher.name ILIKE %s")
                    query_params.append(f"%{search_teacher_name}%")
                if search_precio:
                    query_conditions.append("course.precio = %s")
                    query_params.append(search_precio)
                if search_cupo_disponible:
                    query_conditions.append("course.cupo_disponible = %s")
                    query_params.append(search_cupo_disponible)

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"
                nombre_field = f"course.nombre->>'{search_nombre2}'"

                # Consulta principal con promedio de calificaciones
                query = f"""
                    SELECT 
                        course.id, 
                        course.name, 
                        teacher.name, 
                        course.precio, 
                        course.cupo_disponible, 
                        {nombre_field} AS nombre_traducido,
                        AVG(course_alumn_rel.calificacion) AS media
                    FROM course
                    JOIN teacher ON course.teacher_id = teacher.id
                    LEFT JOIN course_alumn_rel ON course.id = course_alumn_rel.course_id
                    WHERE {where_clause}
                    GROUP BY course.id, teacher.name, course.name, course.precio, course.cupo_disponible, {nombre_field}
                    ORDER BY course.id
                    LIMIT %s OFFSET %s;
                """

                query_params_full = query_params + [limit, offset]
                cur.execute(query, query_params_full)
                rows = cur.fetchall()

                # Conteo total de cursos (sin JOIN para evitar duplicados)
                count_query = f"""
                    SELECT COUNT(*)
                    FROM course
                    JOIN teacher ON course.teacher_id = teacher.id
                    WHERE {where_clause};
                """
                cur.execute(count_query, query_params)
                total_cursos = cur.fetchone()[0]

                course_dict = [
                    {
                        "id": row[0],
                        "name": row[1],
                        "teacher_name": row[2],
                        "precio": float(row[3]) if row[3] is not None else None,
                        "cupo_disponible": row[4],
                        "nombre": row[5],
                        "media": float(row[6]) if row[6] is not None else None
                    }
                    for row in rows
                ]

    except Exception as e:
        print(f"Error al obtener clases: {e}")

    has_next = len(course_dict) == limit

    return render_template(
        'menu.html',
        course_data=course_dict,
        page=page,
        has_next=has_next,
        total_cursos=total_cursos,
        search_nombre=search_nombre,
        search_teacher_name=search_teacher_name,
        search_precio=search_precio,
        search_cupo_disponible=search_cupo_disponible,
        search_nombre2=search_nombre2
    )

@app.route('/alumnos_audit_url')
def alumnos_audit():
    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit
    search_operation = request.args.get('search_operation', '')
    search_stamp = request.args.get('search_stamp', '')
    search_user_id = request.args.get('search_user_id', '')
    search_nombre = request.args.get('search_nombre', '')
    search_apellido = request.args.get('search_apellido', '')
    search_direccion = request.args.get('search_direccion', '')
    search_cumpleanos = request.args.get('search_cumpleanos', '')
    search_last_modified = request.args.get('search_last_modified', '')
    search_hash_password = request.args.get('search_hash_password', '')

    config = load_config()
    rows = []  # Se inicializa en vacío para evitar UnboundLocalError
    total_audit_alumnos = 0  # Se inicializa para evitar problemas en caso de error

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                query_conditions = []
                query_params = []

                if search_nombre:
                    query_conditions.append("first_name ILIKE %s")
                    query_params.append(f"%{search_nombre}%")
                if search_apellido:
                    query_conditions.append("last_name ILIKE %s")
                    query_params.append(f"%{search_apellido}%")
                if search_direccion:
                    query_conditions.append("street_address ILIKE %s")
                    query_params.append(f"%{search_direccion}%")
                if search_operation:
                    query_conditions.append("operation ILIKE %s")
                    query_params.append(f"%{search_operation}%")

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                query = f"""
                    SELECT operation, stamp, userid, id, first_name, last_name, street_address, 
                           TO_CHAR(birthday, 'YYYY-MM-DD'), lastmodified, hash_password
                    FROM alumn_audit
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT %s OFFSET %s;
                """
                
                query_params.extend([limit, offset])
                cur.execute(query, tuple(query_params))
                rows = cur.fetchall()  # Se asigna un valor a rows

                count_query = f"SELECT COUNT(*) FROM alumn_audit WHERE {where_clause};"
                cur.execute(count_query, tuple(query_params[:-2]))  # Evita incluir LIMIT y OFFSET
                total_audit_alumnos = cur.fetchone()[0]

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error en la consulta: {error}")

    alumnos_audit_dict = [
        {
            "operation": u[0], "stamp": u[1], "userid": u[2], "id": u[3],
            "first_name": u[4], "last_name": u[5], "street_address": u[6],
            "birthday": u[7], "lastmodified": u[8], "hash_password": u[9]
        }
        for u in rows
    ]
    
    print("Datos recuperados:", alumnos_audit_dict)



    has_next = len(alumnos_audit_dict) == limit
    return render_template(
    'menu.html', 
    alumnos_audit_data=alumnos_audit_dict, 
    page=page, 
    has_next=has_next,
    total_audit_alumnos=total_audit_alumnos,  # Coincide con el HTML
    search_nombre=search_nombre, 
    search_apellido=search_apellido, 
    search_direccion=search_direccion,
    search_cumpleanos=search_cumpleanos, 
    search_operation=search_operation, 
    search_stamp=search_stamp,
    search_last_modified=search_last_modified, 
    search_hash_password=search_hash_password,
    search_user_id=search_user_id
)



@app.route('/course_audit_url')
def course_audit():
    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit

    search_operation = request.args.get('search_operation', '')
    search_stamp = request.args.get('search_stamp', '')
    search_course_id = request.args.get('search_course_id', '')
    search_teacher_id = request.args.get('search_teacher_id', '')
    search_name = request.args.get('search_name', '')
    

    config = load_config()
    rows = []
    total_audit_courses = 0

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                query_conditions = []
                query_params = []

                if search_operation:
                    query_conditions.append("operation ILIKE %s")
                    query_params.append(f"%{search_operation}%")
                if search_stamp:
                    query_conditions.append("stamp::TEXT ILIKE %s")
                    query_params.append(f"%{search_stamp}%")
                if search_course_id:
                    query_conditions.append("course_id ILIKE %s")
                    query_params.append(f"%{search_course_id}%")
                if search_teacher_id:
                    query_conditions.append("teacher_id::TEXT ILIKE %s")
                    query_params.append(f"%{search_teacher_id}%")
                if search_name:
                    query_conditions.append("name ILIKE %s")
                    query_params.append(f"%{search_name}%")

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                query = f"""
                    SELECT operation, stamp, course_id, id, teacher_id, name, lastmodified, precio, cupo_disponible
                    FROM course_audit
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT %s OFFSET %s;
                """
                
                query_params.extend([limit, offset])
                cur.execute(query, tuple(query_params))
                rows = cur.fetchall()

                count_query = f"SELECT COUNT(*) FROM course_audit WHERE {where_clause};"
                cur.execute(count_query, tuple(query_params[:-2]))
                total_audit_courses = cur.fetchone()[0]

    except Exception as error:
        print(f"Error en course_audit: {error}")

    courses_audit_dict = [
        {
            "operation": u[0], "stamp": u[1], "course_id": u[2], "id": u[3],
            "teacher_id": u[4], "name": u[5], "lastmodified": u[6],
            "precio": u[7], "cupo_disponible": u[8]
        }
        for u in rows
    ]

    has_next = len(courses_audit_dict) == limit
    print("Datos recuperados:", courses_audit_dict)
    return render_template(
        'menu.html', 
        courses_audit_data=courses_audit_dict, 
        page=page, 
        has_next=has_next,
        total_audit_courses=total_audit_courses,
        search_operation=search_operation, 
        search_stamp=search_stamp,
        search_course_id=search_course_id,
        search_teacher_id=search_teacher_id,
        search_name=search_name
    )


@app.route('/teacher_audit_url')
def teacher_audit():
    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit

    search_operation = request.args.get('search_operation', '')
    search_stamp = request.args.get('search_stamp', '')
    search_userid = request.args.get('search_userid', '')
    search_name = request.args.get('search_name', '')


    config = load_config()
    rows = []
    total_audit_teachers = 0

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                query_conditions = []
                query_params = []

                if search_operation:
                    query_conditions.append("operation ILIKE %s")
                    query_params.append(f"%{search_operation}%")
                if search_stamp:
                    query_conditions.append("stamp::TEXT ILIKE %s")
                    query_params.append(f"%{search_stamp}%")
                if search_userid:
                    query_conditions.append("userid ILIKE %s")
                    query_params.append(f"%{search_userid}%")
                if search_name:
                    query_conditions.append("name ILIKE %s")
                    query_params.append(f"%{search_name}%")

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                query = f"""
                    SELECT operation, stamp, userid, id, name, lastmodified
                    FROM teacher_audit
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT %s OFFSET %s;
                """
                
                query_params.extend([limit, offset])
                cur.execute(query, tuple(query_params))
                rows = cur.fetchall()

                count_query = f"SELECT COUNT(*) FROM teacher_audit WHERE {where_clause};"
                cur.execute(count_query, tuple(query_params[:-2]))
                total_audit_teachers = cur.fetchone()[0]

    except Exception as error:
        print(f"Error en teacher_audit: {error}")

    teachers_audit_dict = [
        {
            "operation": u[0], "stamp": u[1], "userid": u[2], "id": u[3],
            "name": u[4], "lastmodified": u[5]
        }
        for u in rows
    ]

    has_next = len(teachers_audit_dict) == limit

    return render_template(
        'menu.html', 
        teachers_audit_data=teachers_audit_dict, 
        page=page, 
        has_next=has_next,
        total_audit_teachers=total_audit_teachers,
        search_operation=search_operation, 
        search_stamp=search_stamp,
        search_userid=search_userid,
        search_name=search_name
    )



@app.route('/matriculados_audit_url')
def matriculados_audit():
    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit

    search_operation = request.args.get('search_operation', '')
    search_stamp = request.args.get('search_stamp', '')
    search_userid = request.args.get('search_userid', '')
    search_alumn_id = request.args.get('search_alumn_id', '')
    search_course_id = request.args.get('search_course_id', '')

    config = load_config()
    rows = []
    total_matriculados_audit = 0

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                query_conditions = []
                query_params = []

                if search_operation:
                    query_conditions.append("operation ILIKE %s")
                    query_params.append(f"%{search_operation}%")
                if search_stamp:
                    query_conditions.append("stamp::TEXT ILIKE %s")
                    query_params.append(f"%{search_stamp}%")
                if search_userid:
                    query_conditions.append("userid ILIKE %s")
                    query_params.append(f"%{search_userid}%")
                if search_alumn_id:
                    query_conditions.append("alumn_id::TEXT ILIKE %s")
                    query_params.append(f"%{search_alumn_id}%")
                if search_course_id:
                    query_conditions.append("course_id::TEXT ILIKE %s")
                    query_params.append(f"%{search_course_id}%")

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                query = f"""
                    SELECT operation, stamp, userid, id, alumn_id, course_id, lastmodified
                    FROM course_alumn_rel_audit
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT %s OFFSET %s;
                """
                
                query_params.extend([limit, offset])
                cur.execute(query, tuple(query_params))
                rows = cur.fetchall()

                count_query = f"SELECT COUNT(*) FROM course_alumn_rel_audit WHERE {where_clause};"
                cur.execute(count_query, tuple(query_params[:-2]))
                total_matriculados_audit = cur.fetchone()[0]

    except Exception as error:
        print(f"Error en course_alumn_rel_audit: {error}")

    matriculados_audit_dict = [
        {
            "operation": u[0], "stamp": u[1], "userid": u[2], "id": u[3],
            "alumn_id": u[4], "course_id": u[5], "lastmodified": u[6]
        }
        for u in rows
    ]

    has_next = len(matriculados_audit_dict) == limit

    return render_template(
        'menu.html',
        matriculados_audit_data=matriculados_audit_dict,
        page=page,
        has_next=has_next,
        total_matriculados_audit=total_matriculados_audit,
        search_operation=search_operation,
        search_stamp=search_stamp,
        search_userid=search_userid,
        search_alumn_id=search_alumn_id,
        search_course_id=search_course_id
    )


# Función para exportar alumnos a Excel
@app.route('/export/alumnos/excel', methods=['GET'])
def export_alumnos_excel():
    config = load_config()
    search_params = {key: request.args.get(key, '') for key in [
        'search_nombre', 'search_apellido', 'search_direccion',
        'search_saldo', 'search_fecha_inicio', 'search_fecha_fin',
        'search_birthday_inicio', 'search_birthday_fin'
    ]}
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query_conditions = []
                query_params = []

                if search_params['search_nombre']:
                    query_conditions.append("first_name ILIKE %s")
                    query_params.append(f"%{search_params['search_nombre']}%")
                if search_params['search_apellido']:
                    query_conditions.append("last_name ILIKE %s")
                    query_params.append(f"%{search_params['search_apellido']}%")
                if search_params['search_direccion']:
                    query_conditions.append("street_address ILIKE %s")
                    query_params.append(f"%{search_params['search_direccion']}%")
                if search_params['search_saldo']:
                    query_conditions.append("saldo = %s")
                    query_params.append(search_params['search_saldo'])
                if search_params['search_birthday_inicio'] and search_params['search_birthday_fin']:
                    query_conditions.append("birthday BETWEEN %s AND %s")
                    query_params.extend([search_params['search_birthday_inicio'], search_params['search_birthday_fin']])
                if search_params['search_fecha_inicio'] and search_params['search_fecha_fin']:
                    query_conditions.append("lastmodified BETWEEN %s AND %s")
                    query_params.extend([search_params['search_fecha_inicio'], search_params['search_fecha_fin']])

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"
                
                query = f"""
                    SELECT id, first_name, last_name, street_address, 
                           TO_CHAR(birthday, 'YYYY-MM-DD') as birthday, 
                           TO_CHAR(lastmodified, 'YYYY-MM-DD HH24:MI:SS') as lastmodified, 
                           saldo
                    FROM alumn
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT 1000;
                """
                
                cur.execute(query, tuple(query_params))
                alumnos = cur.fetchall()
                
                df = pd.DataFrame(alumnos)
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    df.to_excel(writer, index=False, sheet_name='Alumnos')
                output.seek(0)
                
                return send_file(
                    output,
                    as_attachment=True,
                    download_name="alumnos.xlsx",
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Función para exportar profesores a Excel
@app.route('/export/profesores/excel', methods=['GET'])
def export_profesores_excel():
    config = load_config()
    search_id = request.args.get('search_id', '')
    search_nombre = request.args.get('search_nombre', '')
    search_fecha_inicio = request.args.get('search_fecha_inicio', '')
    search_fecha_fin = request.args.get('search_fecha_fin', '')
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query_conditions = []
                query_params = []

                if search_id:
                    query_conditions.append("id = %s")
                    query_params.append(search_id)
                if search_nombre:
                    query_conditions.append("name ILIKE %s")
                    query_params.append(f"%{search_nombre}%")
                if search_fecha_inicio and search_fecha_fin:
                    query_conditions.append("lastmodified BETWEEN %s AND %s")
                    query_params.extend([search_fecha_inicio, search_fecha_fin])

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"
                
                query = f"""
                    SELECT id, name, TO_CHAR(lastmodified, 'YYYY-MM-DD HH24:MI:SS') as lastmodified, nota
                    FROM teacher
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT 1000;
                """
                
                cur.execute(query, tuple(query_params))
                profesores = cur.fetchall()
                
                df = pd.DataFrame(profesores)
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    df.to_excel(writer, index=False, sheet_name='Profesores')
                output.seek(0)
                
                return send_file(
                    output,
                    as_attachment=True,
                    download_name="profesores.xlsx",
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Función para exportar cursos a Excel (la original mejorada)
@app.route('/export/cursos/excel', methods=['GET'])
def export_cursos_excel():
    config = load_config()
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, name, precio, cupo_disponible FROM course ORDER BY id LIMIT 1000")
                cursos = cur.fetchall()
                df = pd.DataFrame(cursos)
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    df.to_excel(writer, index=False, sheet_name='Cursos')
                output.seek(0)
                return send_file(
                    output,
                    as_attachment=True,
                    download_name="cursos.xlsx",
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Función para exportar alumnos a PDF
@app.route('/export/alumnos/pdf', methods=['GET'])
def export_alumnos_pdf():
    config = load_config()
    search_params = {key: request.args.get(key, '') for key in [
        'search_nombre', 'search_apellido', 'search_direccion',
        'search_saldo', 'search_fecha_inicio', 'search_fecha_fin',
        'search_birthday_inicio', 'search_birthday_fin'
    ]}
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query_conditions = []
                query_params = []

                if search_params['search_nombre']:
                    query_conditions.append("first_name ILIKE %s")
                    query_params.append(f"%{search_params['search_nombre']}%")
                if search_params['search_apellido']:
                    query_conditions.append("last_name ILIKE %s")
                    query_params.append(f"%{search_params['search_apellido']}%")
                if search_params['search_direccion']:
                    query_conditions.append("street_address ILIKE %s")
                    query_params.append(f"%{search_params['search_direccion']}%")
                if search_params['search_saldo']:
                    query_conditions.append("saldo = %s")
                    query_params.append(search_params['search_saldo'])
                if search_params['search_birthday_inicio'] and search_params['search_birthday_fin']:
                    query_conditions.append("birthday BETWEEN %s AND %s")
                    query_params.extend([search_params['search_birthday_inicio'], search_params['search_birthday_fin']])
                if search_params['search_fecha_inicio'] and search_params['search_fecha_fin']:
                    query_conditions.append("lastmodified BETWEEN %s AND %s")
                    query_params.extend([search_params['search_fecha_inicio'], search_params['search_fecha_fin']])

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"
                
                query = f"""
                    SELECT id, first_name, last_name, street_address, 
                           TO_CHAR(birthday, 'YYYY-MM-DD') as birthday, 
                           TO_CHAR(lastmodified, 'YYYY-MM-DD HH24:MI:SS') as lastmodified, 
                           saldo
                    FROM alumn
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT 1000;
                """
                
                cur.execute(query, tuple(query_params))
                alumnos = cur.fetchall()
                
                # Construcción del HTML
                html = """
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        h1 { text-align: center; }
                        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                        th, td { border: 1px solid black; padding: 8px; text-align: left; }
                        th { background-color: #007bff; color: white; }
                    </style>
                </head>
                <body>
                    <h1>Lista de Alumnos</h1>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Nombre</th>
                            <th>Apellido</th>
                            <th>Dirección</th>
                            <th>Cumpleaños</th>
                            <th>Últ. modificación</th>
                            <th>Saldo</th>
                        </tr>"""
                
                for alumno in alumnos:
                    html += f"""
                        <tr>
                            <td>{alumno['id']}</td>
                            <td>{alumno['first_name']}</td>
                            <td>{alumno['last_name']}</td>
                            <td>{alumno['street_address']}</td>
                            <td>{alumno['birthday']}</td>
                            <td>{alumno['lastmodified']}</td>
                            <td>{alumno['saldo']}</td>
                        </tr>"""

                html += """
                    </table>
                </body>
                </html>
                """

                # Configurar la ruta manual de wkhtmltopdf
                pdfkit_config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
                pdf = pdfkit.from_string(html, False, configuration=pdfkit_config)
                
                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'attachment; filename=alumnos.pdf'
                return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Función para exportar profesores a PDF
@app.route('/export/profesores/pdf', methods=['GET'])
def export_profesores_pdf():
    config = load_config()
    search_id = request.args.get('search_id', '')
    search_nombre = request.args.get('search_nombre', '')
    search_fecha_inicio = request.args.get('search_fecha_inicio', '')
    search_fecha_fin = request.args.get('search_fecha_fin', '')
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query_conditions = []
                query_params = []

                if search_id:
                    query_conditions.append("id = %s")
                    query_params.append(search_id)
                if search_nombre:
                    query_conditions.append("name ILIKE %s")
                    query_params.append(f"%{search_nombre}%")
                if search_fecha_inicio and search_fecha_fin:
                    query_conditions.append("lastmodified BETWEEN %s AND %s")
                    query_params.extend([search_fecha_inicio, search_fecha_fin])

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"
                
                query = f"""
                    SELECT id, name, TO_CHAR(lastmodified, 'YYYY-MM-DD HH24:MI:SS') as lastmodified, nota
                    FROM teacher
                    WHERE {where_clause}
                    ORDER BY id
                    LIMIT 1000;
                """
                
                cur.execute(query, tuple(query_params))
                profesores = cur.fetchall()
                
                # Construcción del HTML
                html = """
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        h1 { text-align: center; }
                        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                        th, td { border: 1px solid black; padding: 8px; text-align: left; }
                        th { background-color: #007bff; color: white; }
                    </style>
                </head>
                <body>
                    <h1>Lista de Profesores</h1>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Nombre</th>
                            <th>Última modificación</th>
                            <th>Nota</th>
                        </tr>"""
                
                for profesor in profesores:
                    html += f"""
                        <tr>
                            <td>{profesor['id']}</td>
                            <td>{profesor['name']}</td>
                            <td>{profesor['lastmodified']}</td>
                            <td>{profesor['nota']}</td>
                        </tr>"""

                html += """
                    </table>
                </body>
                </html>
                """

                # Configurar la ruta manual de wkhtmltopdf
                pdfkit_config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
                pdf = pdfkit.from_string(html, False, configuration=pdfkit_config)
                
                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'attachment; filename=profesores.pdf'
                return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Función para exportar cursos a PDF (la original mejorada)
@app.route('/export/cursos/pdf', methods=['GET'])
def export_cursos_pdf():
    config = load_config()
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, name, precio, cupo_disponible FROM course ORDER BY id LIMIT 1000")
                cursos = cur.fetchall()
                
                # Construcción del HTML
                html = """
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        h1 { text-align: center; }
                        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                        th, td { border: 1px solid black; padding: 8px; text-align: left; }
                        th { background-color: #007bff; color: white; }
                    </style>
                </head>
                <body>
                    <h1>Lista de Cursos</h1>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Nombre</th>
                            <th>Precio</th>
                            <th>Cupo Disponible</th>
                        </tr>"""
                
                for curso in cursos:
                    html += f"""
                        <tr>
                            <td>{curso['id']}</td>
                            <td>{curso['name']}</td>
                            <td>{curso['precio']}</td>
                            <td>{curso['cupo_disponible']}</td>
                        </tr>"""

                html += """
                    </table>
                </body>
                </html>
                """

                # Configurar la ruta manual de wkhtmltopdf
                pdfkit_config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
                pdf = pdfkit.from_string(html, False, configuration=pdfkit_config)
                
                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'attachment; filename=cursos.pdf'
                return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Función para exportar datos a CSV (genérica)
@app.route('/export/csv', methods=['GET'])
def export_csv():
    tipo = request.args.get('tipo', '')
    config = load_config()
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if tipo == 'alumnos':
                    # Usar los mismos filtros que en la exportación a Excel
                    search_params = {key: request.args.get(key, '') for key in [
                        'search_nombre', 'search_apellido', 'search_direccion',
                        'search_saldo', 'search_fecha_inicio', 'search_fecha_fin',
                        'search_birthday_inicio', 'search_birthday_fin'
                    ]}
                    
                    query_conditions = []
                    query_params = []

                    if search_params['search_nombre']:
                        query_conditions.append("first_name ILIKE %s")
                        query_params.append(f"%{search_params['search_nombre']}%")
                    if search_params['search_apellido']:
                        query_conditions.append("last_name ILIKE %s")
                        query_params.append(f"%{search_params['search_apellido']}%")
                    if search_params['search_direccion']:
                        query_conditions.append("street_address ILIKE %s")
                        query_params.append(f"%{search_params['search_direccion']}%")
                    if search_params['search_saldo']:
                        query_conditions.append("saldo = %s")
                        query_params.append(search_params['search_saldo'])
                    if search_params['search_birthday_inicio'] and search_params['search_birthday_fin']:
                        query_conditions.append("birthday BETWEEN %s AND %s")
                        query_params.extend([search_params['search_birthday_inicio'], search_params['search_birthday_fin']])
                    if search_params['search_fecha_inicio'] and search_params['search_fecha_fin']:
                        query_conditions.append("lastmodified BETWEEN %s AND %s")
                        query_params.extend([search_params['search_fecha_inicio'], search_params['search_fecha_fin']])

                    where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"
                    
                    query = f"""
                        SELECT id, first_name, last_name, street_address, 
                               TO_CHAR(birthday, 'YYYY-MM-DD') as birthday, 
                               TO_CHAR(lastmodified, 'YYYY-MM-DD HH24:MI:SS') as lastmodified, 
                               saldo
                        FROM alumn
                        WHERE {where_clause}
                        ORDER BY id
                        LIMIT 1000;
                    """
                    
                    cur.execute(query, tuple(query_params))
                    data = cur.fetchall()
                    filename = "alumnos.csv"
                
                elif tipo == 'profesores':
                    search_id = request.args.get('search_id', '')
                    search_nombre = request.args.get('search_nombre', '')
                    search_fecha_inicio = request.args.get('search_fecha_inicio', '')
                    search_fecha_fin = request.args.get('search_fecha_fin', '')
                    
                    query_conditions = []
                    query_params = []

                    if search_id:
                        query_conditions.append("id = %s")
                        query_params.append(search_id)
                    if search_nombre:
                        query_conditions.append("name ILIKE %s")
                        query_params.append(f"%{search_nombre}%")
                    if search_fecha_inicio and search_fecha_fin:
                        query_conditions.append("lastmodified BETWEEN %s AND %s")
                        query_params.extend([search_fecha_inicio, search_fecha_fin])

                    where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"
                    
                    query = f"""
                        SELECT id, name, TO_CHAR(lastmodified, 'YYYY-MM-DD HH24:MI:SS') as lastmodified, nota
                        FROM teacher
                        WHERE {where_clause}
                        ORDER BY id
                        LIMIT 1000;
                    """
                    
                    cur.execute(query, tuple(query_params))
                    data = cur.fetchall()
                    filename = "profesores.csv"
                
                elif tipo == 'cursos':
                    cur.execute("SELECT id, name, precio, cupo_disponible FROM course ORDER BY id LIMIT 1000")
                    data = cur.fetchall()
                    filename = "cursos.csv"
                
                else:
                    return jsonify({'error': 'Tipo de datos no válido'}), 400
                
                # Crear un dataframe con los datos
                df = pd.DataFrame(data)
                
                # Crear un buffer para guardar el CSV
                csv_buffer = io.StringIO()
                df.to_csv(csv_buffer, index=False)
                
                # Preparar la respuesta
                response = make_response(csv_buffer.getvalue())
                response.headers['Content-Disposition'] = f'attachment; filename={filename}'
                response.headers['Content-type'] = 'text/csv'
                
                return response
                
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/import/alumnos/excel', methods=['GET', 'POST'])
def import_alumnos_excel():
    if request.method == 'GET':

        return render_template('importar_excel.html')

    if 'file' not in request.files:
        return jsonify({'error': 'No se encontró el archivo.'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No se seleccionó ningún archivo.'}), 400

    if not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({'error': 'El archivo debe ser un Excel (.xlsx o .xls).'}), 400

    config = load_config()
    try:
        df = pd.read_excel(file)

        required_columns = ['first_name', 'last_name', 'street_address', 'birthday', 'saldo']
        missing_columns = [col for col in required_columns if col not in df.columns]

        if missing_columns:
            return jsonify({'error': f'Faltan columnas requeridas: {", ".join(missing_columns)}'}), 400

        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                insert_query = """
                    INSERT INTO alumn (first_name, last_name, street_address, birthday, saldo)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE 
                    SET first_name = EXCLUDED.first_name,
                        last_name = EXCLUDED.last_name,
                        street_address = EXCLUDED.street_address,
                        birthday = EXCLUDED.birthday,
                        saldo = EXCLUDED.saldo;
                """

                rows_inserted = 0
                for _, row in df.iterrows():
                    try:
                        cur.execute(insert_query, (
                            row['first_name'],
                            row['last_name'],
                            row['street_address'],
                            row['birthday'],
                            row['saldo']
                        ))
                        rows_inserted += 1
                    except Exception as e:
                        print(f"Error en fila: {e}")

                conn.commit()

        return jsonify({'message': f'Importación exitosa. {rows_inserted} registros procesados.'}), 200

    except pd.errors.EmptyDataError:
        return jsonify({'error': 'El archivo Excel está vacío.'}), 400
    except Exception as e:
        return jsonify({'error': f'Error durante la importación: {str(e)}'}), 500

@app.route('/import/excel', methods=['POST'])
def import_excel():
    if 'file' not in request.files:
        return jsonify({'error': 'No se encontró el archivo.'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No se seleccionó ningún archivo.'}), 400
    
    config = load_config()
    try:
        df = pd.read_excel(file)
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                for _, row in df.iterrows():
                    cur.execute(
                        "INSERT INTO course (name, precio, cupo_disponible) VALUES (%s, %s, %s)",
                        (row['name'], row['precio'], row['cupo_disponible'])
                    )
                conn.commit()
        return jsonify({'message': 'Datos importados correctamente.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/ver_redis')
def ver_redis():
    if not redis_client:
        return "Redis no está disponible", 503

    claves = []
    for key in redis_client.scan_iter("*"):
        try:
            key_str = key.decode("utf-8")
            raw_value = redis_client.get(key)
            ttl = redis_client.ttl(key)

            value_str = None
            is_binary = False

            # Intenta como texto
            try:
                value_str = raw_value.decode('utf-8')
                try:
                    value_json = json.loads(value_str)
                    value_str = json.dumps(value_json, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    pass
            except UnicodeDecodeError:
                is_binary = True
                if key_str.startswith("session:"):
                    value_str = "Valor binario no legible (pickle/session)"
                else:
                    value_str = base64.b64encode(raw_value).decode("ascii")

            claves.append({
                "clave": key_str,
                "valor": value_str,
                "ttl": ttl
            })
        except Exception as e:
            claves.append({
                "clave": key.decode('utf-8'),
                "valor": f"Error al obtener valor: {str(e)}",
                "ttl": "?"
            })

    return render_template('ver_redis.html', claves=claves)

@app.route('/ejecutar_sql', methods=['POST'])
def ejecutar_sql():
    if 'usuario' not in session:
        return jsonify({'error': 'Acceso no autorizado'}), 401
        
    data = request.get_json()
    consulta = data.get('consulta')
    
    # Lista de palabras prohibidas para evitar operaciones peligrosas
    palabras_prohibidas = ['DROP', 'TRUNCATE', 'DELETE FROM', 'ALTER ', 'CREATE ']
    for palabra in palabras_prohibidas:
        if palabra in consulta.upper() and not consulta.upper().startswith('DELETE FROM course_alumn_rel') and not consulta.upper().startswith('DELETE FROM alumn WHERE'):
            return jsonify({'error': 'Operación no permitida'}), 403
    
    config = load_config()
    resultados = []
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(consulta)
                
                # Si la consulta es un SELECT, devolver resultados
                if consulta.strip().upper().startswith('SELECT'):
                    rows = cur.fetchall()
                    for row in rows:
                        resultados.append(dict(row))
                    return jsonify(resultados)
                    
                # Si es una operación que modifica datos
                else:
                    conn.commit()
                    return jsonify({'message': 'Operación completada', 'rowcount': cur.rowcount})
                    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/consultar_elasticsearch', methods=['POST'])
def consultar_elasticsearch():
    if 'usuario' not in session:
        return jsonify({'error': 'Acceso no autorizado'}), 401
        
    data = request.get_json()
    usuario_id = data.get('usuario_id')
    
    try:
        # Construir consulta para Elasticsearch
        query = {
            "query": {
                "match": {
                    "usuario_id": usuario_id
                }
            },
            "size": 10,
            "sort": [
                {
                    "timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
        
        # Realizar consulta a Elasticsearch
        resultados = es.search(index=INDEX_LOGS, body=query)
        
        # Formatear resultados
        logs = []
        for hit in resultados['hits']['hits']:
            logs.append(hit['_source'])
            
        return jsonify(logs)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/geolocalizacion')
def geolocalizacion():
    """Página principal de geolocalización"""
    if 'usuario' not in session:
        return redirect(url_for('home'))
    return render_template('geolocalizacion.html')

@app.route('/api/ubicaciones')
def api_ubicaciones():
    """API para obtener todas las ubicaciones"""
    config = load_config()
    ubicaciones = []
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, nombre, tipo, direccion, descripcion, 
                           ST_X(geom) as longitud, ST_Y(geom) as latitud 
                    FROM ubicaciones
                """)
                ubicaciones = cur.fetchall()
    except Exception as e:
        logging.error(f"Error al obtener ubicaciones: {e}")
        return jsonify({"error": str(e)}), 500
        
    return jsonify(ubicaciones)

@app.route('/api/alumnos/ubicaciones')
def api_alumnos_ubicaciones():
    """API para obtener ubicaciones de alumnos"""
    config = load_config()
    alumnos = []
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, first_name, last_name, 
                           ST_X(geom) as longitud, ST_Y(geom) as latitud 
                    FROM alumn
                    WHERE geom IS NOT NULL
                """)
                alumnos = cur.fetchall()
    except Exception as e:
        logging.error(f"Error al obtener ubicaciones de alumnos: {e}")
        return jsonify({"error": str(e)}), 500
        
    return jsonify(alumnos)

@app.route('/api/profesores/ubicaciones')
def api_profesores_ubicaciones():
    """API para obtener ubicaciones de profesores"""
    config = load_config()
    profesores = []
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, name, 
                           ST_X(geom) as longitud, ST_Y(geom) as latitud 
                    FROM teacher
                    WHERE geom IS NOT NULL
                """)
                profesores = cur.fetchall()
    except Exception as e:
        logging.error(f"Error al obtener ubicaciones de profesores: {e}")
        return jsonify({"error": str(e)}), 500
        
    return jsonify(profesores)

@app.route('/api/clases/ubicaciones')
def api_clases_ubicaciones():
    """API para obtener ubicaciones de clases"""
    config = load_config()
    clases = []
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT c.id, c.name, t.name as teacher_name, 
                           ST_X(c.geom) as longitud, ST_Y(c.geom) as latitud 
                    FROM course c
                    JOIN teacher t ON c.teacher_id = t.id
                    WHERE c.geom IS NOT NULL
                """)
                clases = cur.fetchall()
    except Exception as e:
        logging.error(f"Error al obtener ubicaciones de clases: {e}")
        return jsonify({"error": str(e)}), 500
        
    return jsonify(clases)

@app.route('/api/ubicaciones/cercanas')
def api_ubicaciones_cercanas():
    """API para obtener ubicaciones cercanas a un punto"""
    lat = request.args.get('lat', type=float)
    lon = request.args.get('lon', type=float)
    radio = request.args.get('radio', default=1000, type=float)
    
    if lat is None or lon is None:
        return jsonify({"error": "Latitud y longitud son obligatorias"}), 400
    
    config = load_config()
    cercanas = []
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, nombre, tipo, distancia 
                    FROM find_nearby_locations(%s, %s, %s)
                """, (lat, lon, radio))
                cercanas = cur.fetchall()
    except Exception as e:
        logging.error(f"Error al obtener ubicaciones cercanas: {e}")
        return jsonify({"error": str(e)}), 500
        
    return jsonify(cercanas)

@app.route('/api/actualizar_ubicacion', methods=['POST'])
def api_actualizar_ubicacion():
    """API para actualizar la ubicación de un usuario"""
    if 'usuario' not in session:
        return jsonify({"error": "No autorizado"}), 401
    
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Datos no proporcionados"}), 400
    
    lat = data.get('lat')
    lon = data.get('lon')
    tipo = data.get('tipo', 'alumno')  # alumno, profesor, clase
    id = data.get('id')
    
    if not all([lat, lon, id]):
        return jsonify({"error": "Faltan datos obligatorios"}), 400
    
    config = load_config()
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                if tipo == 'alumno':
                    cur.execute("""
                        UPDATE alumn 
                        SET geom = ST_SetSRID(ST_MakePoint(%s, %s), 4326)
                        WHERE id = %s
                    """, (lon, lat, id))
                elif tipo == 'profesor':
                    cur.execute("""
                        UPDATE teacher 
                        SET geom = ST_SetSRID(ST_MakePoint(%s, %s), 4326)
                        WHERE id = %s
                    """, (lon, lat, id))
                elif tipo == 'clase':
                    cur.execute("""
                        UPDATE course 
                        SET geom = ST_SetSRID(ST_MakePoint(%s, %s), 4326)
                        WHERE id = %s
                    """, (lon, lat, id))
                else:
                    return jsonify({"error": "Tipo no válido"}), 400
                
                conn.commit()
                
                if cur.rowcount == 0:
                    return jsonify({"error": "No se encontró el registro"}), 404
                
                return jsonify({"mensaje": "Ubicación actualizada correctamente"})
    except Exception as e:
        logging.error(f"Error al actualizar ubicación: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ruta', methods=['GET', 'POST'])
def api_ruta():
    """API para obtener la ruta entre dos puntos"""
    origen_id = request.args.get('origen_id', type=int)
    destino_id = request.args.get('destino_id', type=int)
    tipo_origen = request.args.get('tipo_origen', default='alumno')
    tipo_destino = request.args.get('tipo_destino', default='ubicacion')
    
    if origen_id is None or destino_id is None:
        return jsonify({"error": "Origen y destino son obligatorios"}), 400
    
    config = load_config()
    
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Primero obtenemos las coordenadas del origen
                if tipo_origen == 'alumno':
                    cur.execute("SELECT ST_X(geom) as lon, ST_Y(geom) as lat FROM alumn WHERE id = %s", (origen_id,))
                elif tipo_origen == 'profesor':
                    cur.execute("SELECT ST_X(geom) as lon, ST_Y(geom) as lat FROM teacher WHERE id = %s", (origen_id,))
                else:
                    return jsonify({"error": "Tipo de origen no válido"}), 400
                
                origen = cur.fetchone()
                if not origen:
                    return jsonify({"error": "Origen no encontrado"}), 404
                
                # Luego obtenemos las coordenadas del destino
                if tipo_destino == 'ubicacion':
                    cur.execute("SELECT ST_X(geom) as lon, ST_Y(geom) as lat FROM ubicaciones WHERE id = %s", (destino_id,))
                elif tipo_destino == 'clase':
                    cur.execute("SELECT ST_X(geom) as lon, ST_Y(geom) as lat FROM course WHERE id = %s", (destino_id,))
                else:
                    return jsonify({"error": "Tipo de destino no válido"}), 400
                
                destino = cur.fetchone()
                if not destino:
                    return jsonify({"error": "Destino no encontrado"}), 404
                
                # Encontramos los nodos más cercanos en la red
                cur.execute("""
                    SELECT id FROM ways_vertices_pgr 
                    ORDER BY the_geom <-> ST_SetSRID(ST_MakePoint(%s, %s), 4326) 
                    LIMIT 1
                """, (origen['lon'], origen['lat']))
                nodo_origen = cur.fetchone()
                
                cur.execute("""
                    SELECT id FROM ways_vertices_pgr 
                    ORDER BY the_geom <-> ST_SetSRID(ST_MakePoint(%s, %s), 4326) 
                    LIMIT 1
                """, (destino['lon'], destino['lat']))
                nodo_destino = cur.fetchone()
                
                # Calculamos la ruta
                cur.execute("""
                    SELECT seq, node, edge, cost, agg_cost, 
                           ST_AsGeoJSON(geom) as geometry
                    FROM pgr_dijkstra(
                        'SELECT id, source, target, cost, reverse_cost FROM ways',
                        %s, %s, directed := false
                    ) AS di
                    JOIN ways ON di.edge = ways.id
                    ORDER BY seq
                """, (nodo_origen['id'], nodo_destino['id']))
                
                ruta = cur.fetchall()
                
                return jsonify(ruta)
    except Exception as e:
        logging.error(f"Error al obtener ruta: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/resumen_olap")
def resumen_olap():
    conn = psycopg2.connect(**config)
    df = pd.read_sql("SELECT * FROM resumen_olap", conn)
    conn.close()
    return render_template("resumen_olap.html", data=df.to_dict(orient='records'))

# Función para agregar un proceso en segundo plano que procese la cola de logs
def worker_log_queue():
    """
    Proceso en segundo plano que toma logs de la cola y los guarda en Elasticsearch
    """
    while True:
        try:
            # Obtener un log de la cola
            log = log_queue.get(block=True, timeout=1)
            
            # Guardar en Elasticsearch
            es.index(index=INDEX_LOGS, body=log)
            
            # Marcar la tarea como completada
            log_queue.task_done()
            
        except queue.Empty:
            # Si la cola está vacía, esperar un momento
            time.sleep(0.1)
        except Exception as e:
            print(f"Error al procesar log: {e}")


# Iniciar hilo para procesamiento de logs
log_thread = Thread(target=worker_log_queue, daemon=True)
log_thread.start()



config = load_config()



if __name__ == '__main__':
    app.run(debug=True)
import psycopg2






