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
    search_nombre = request.args.get('search_nombre', '')
    config = load_config()
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                #condiciones de búsqueda dinámicamente
                query_conditions = []
                query_params = []

                #condición para el nombre solo si no está vacío
                if search_nombre:
                    query_conditions.append("name ILIKE %s")
                    query_params.append(f"%{search_nombre}%")



                where_clause = " AND ".join(
                    query_conditions) if query_conditions else "1=1"  # "1=1" siempre es verdadero

                # Consulta SQL con condiciones de búsqueda dinámicas
                query = f"""
                                    SELECT id, name,lastmodified, nota
                                    FROM teacher
                                    WHERE {where_clause}
                                    ORDER BY id
                                    LIMIT %s OFFSET %s;
                                """

                # Añadir los parámetros de búsqueda y de paginación
                query_params.extend([limit, offset])

                # Ejecutar la consulta
                cur.execute(query, tuple(query_params))
                rows = cur.fetchall()

                # Ejecutar la consulta de conteo total de alumnos con las mismas condiciones de búsqueda
                count_query = f"SELECT COUNT(*) FROM teacher WHERE {where_clause};"
                cur.execute(count_query, tuple(query_params[:-2]))  # Sin los parámetros de paginación
                total_profesores = cur.fetchone()[0]

    except (Exception, psycopg2.DatabaseError) as error:
        print(error)

    profesores_dict = [{"id": u[0], "name": u[1], "lastmodified": u[2],"nota": u[3]} for u in rows]
    has_next = len(profesores_dict) == limit
    return render_template('menu.html', profesores_data=profesores_dict, page=page, has_next=has_next,
                           total_profesores=total_profesores,
                           search_nombre=search_nombre,
                           
                           )


@app.route('/matriculados_url')
def matriculados():
    page = request.args.get('page', 1, type=int)
    limit = 30
    offset = (page - 1) * limit
    search_alumn_id = request.args.get('search_alumn_id', '').strip()
    search_course_id = request.args.get('search_course_id', '').strip()
    search_lastmodified = request.args.get('search_lastmodified', '').strip()
    
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

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                # Consulta SQL con JOIN para obtener el nombre del profesor
                query = f"""
                    SELECT course_alumn_rel.alumn_id, course_alumn_rel.course_id, course_alumn_rel.lastmodified
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
    search_nombre2 = request.args.get('search_nombre2', 'esp')  # Default to 'esp' if not selected
    config = load_config()

    course_dict = []
    total_cursos = 0

    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor() as cur:
                # Construcción dinámica de condiciones
                query_conditions = []
                query_params = []

                if search_nombre:
                    query_conditions.append("course.name ILIKE %s")
                    query_params.append(f"%{search_nombre}%")

                if search_teacher_name:
                    query_conditions.append("teacher.name ILIKE %s")
                    query_params.append(f"%{search_teacher_name}%")

                where_clause = " AND ".join(query_conditions) if query_conditions else "1=1"

                # Selección dinámica de idioma
                nombre_field = f"course.nombre->'{search_nombre2}'"  # 'esp' or 'eng'

                
                query = f"""
                    SELECT course.id, course.name, teacher.name, course.precio, course.cupo_disponible, {nombre_field}
                    FROM course
                    JOIN teacher ON course.teacher_id = teacher.id
                    WHERE {where_clause}
                    ORDER BY course.id
                    LIMIT %s OFFSET %s;
                """

                query_params.extend([limit, offset])

                # Ejecutar consulta principal
                cur.execute(query, tuple(query_params))
                rows = cur.fetchall()

                # Contar el total de cursos con los filtros aplicados
                count_query = f"SELECT COUNT(*) FROM course JOIN teacher ON course.teacher_id = teacher.id WHERE {where_clause};"
                cur.execute(count_query, tuple(query_params[:-2]))  # Sin los parámetros de paginación
                total_cursos = cur.fetchone()[0]

                # Convertir resultados en diccionario
                course_dict = [
                    {
                        "id": row[0],
                        "name": row[1],
                        "teacher_name": row[2],
                        "precio": row[3],
                        "cupo_disponible": row[4],
                        "nombre": row[5]
                    }
                    for row in rows
                ]

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error al obtener clases: {error}")

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
        search_nombre2=search_nombre2  # Pasar el valor de la selección al HTML
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





@app.route('/export/excel', methods=['GET'])
def export_excel():
    config = load_config()
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, name, precio, cupo_disponible FROM course")
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




@app.route('/export/pdf', methods=['GET'])
def export_pdf():
    config = load_config()
    try:
        with psycopg2.connect(**config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, name, precio, cupo_disponible FROM course order by id limit 2500")
                cursos = cur.fetchall()
                
                # Construcción del HTML manualmente
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







config = load_config()



if __name__ == '__main__':
    app.run(debug=True)
import psycopg2



DB_CONFIG = load_config()


