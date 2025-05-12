from time import time
from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for, send_file, make_response, Response
import sqlite3
from flask_bcrypt import Bcrypt
from flasgger import Swagger
import psycopg2
from datetime import datetime, timedelta
from config import load_config
import hashlib
from sqlalchemy import extract, func, create_engine
from sqlalchemy.orm import sessionmaker
import io
import pandas as pd
import pdfkit
from psycopg2.extras import RealDictCursor, DictCursor
import json
from flask_session import Session
import redis
from elasticsearch import Elasticsearch
import uuid
from threading import Thread
import queue
import pickle
import base64
import csv
import os
import matplotlib.pyplot as plt
import seaborn as sns
from werkzeug.utils import secure_filename
import logging
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import numpy as np
import time as time_module

# Configuración de logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                   filename='app.log')
logger = logging.getLogger(__name__)

# Cargar configuración
db_config = load_config()
log_queue = queue.Queue()
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configuración de Redis para caché
try:
    redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)
    redis_client.ping()
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis_client
    app.config['SESSION_PERMANENT'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_USE_SIGNER'] = True
    logger.info("Redis conectado correctamente")
except redis.exceptions.ConnectionError:
    redis_client = None
    app.config['SESSION_TYPE'] = 'filesystem'
    logger.warning("Redis no disponible. Se usará filesystem para sesiones.")

Session(app)
Swagger(app)
bcrypt = Bcrypt(app)

# Configuración de Elasticsearch
try:
    es = Elasticsearch("http://localhost:9200")
    es_available = es.ping()
    INDEX_LOGS = "logs_usuarios"
    
    # Creación del índice si no existe
    if es_available and not es.indices.exists(index=INDEX_LOGS):
        mappings = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "usuario_id": {"type": "keyword"},
                    "sesion_id": {"type": "keyword"},
                    "ruta": {"type": "keyword"},
                    "funcion": {"type": "keyword"},
                    "parametros": {"type": "object"},
                    "tiempo_respuesta_ms": {"type": "integer"},
                    "usuario_data": {"type": "object"}
                }
            }
        }
        es.indices.create(index=INDEX_LOGS, body=mappings)
        logger.info("Índice Elasticsearch creado correctamente")
except Exception as e:
    es_available = False
    logger.error(f"Error al conectar con Elasticsearch: {e}")

# Configuración para SQLAlchemy (OLAP)
try:
    pg_engine = create_engine(f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['database']}")
    Session_sqlalchemy = sessionmaker(bind=pg_engine)
    logger.info("Motor SQLAlchemy configurado correctamente")
except Exception as e:
    logger.error(f"Error al configurar SQLAlchemy: {e}")

# Directorio para uploads
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Clase para procesar los logs en segundo plano
class LogProcessor(Thread):
    def __init__(self, log_queue, es_client=None):
        Thread.__init__(self)
        self.daemon = True
        self.log_queue = log_queue
        self.es_client = es_client
        self.running = True
        
    def run(self):
        while self.running:
            try:
                # Procesar logs en lotes
                batch = []
                # Recoger hasta 100 logs o esperar 5 segundos
                timeout = time_module.time() + 5
                while len(batch) < 100 and time_module.time() < timeout:
                    try:
                        log = self.log_queue.get(block=True, timeout=0.1)
                        batch.append(log)
                        self.log_queue.task_done()
                    except queue.Empty:
                        break
                
                if batch and self.es_client and es_available:
                    # Preparar operación bulk para Elasticsearch
                    bulk_data = []
                    for log in batch:
                        bulk_data.append({"index": {"_index": INDEX_LOGS}})
                        bulk_data.append(log)
                    
                    # Insertar en Elasticsearch
                    try:
                        self.es_client.bulk(index=INDEX_LOGS, body=bulk_data)
                        logger.info(f"Procesados {len(batch)} logs en Elasticsearch")
                    except Exception as e:
                        logger.error(f"Error al insertar logs en Elasticsearch: {e}")
                        
                        # Guardar logs en archivo como respaldo
                        with open('logs_backup.jsonl', 'a') as f:
                            for log in batch:
                                f.write(json.dumps(log) + '\n')
                
                if not batch:
                    time_module.sleep(0.1)  # Evitar CPU al 100%
                    
            except Exception as e:
                logger.error(f"Error en el procesador de logs: {e}")
                time_module.sleep(1)  # Pausa en caso de error

# Iniciar procesador de logs
log_processor = LogProcessor(log_queue, es)
log_processor.start()

# --- Middleware Flask para capturar logs de actividad ---
@app.before_request
def before_request():
    g.inicio = time()
    # Añadir ID de sesión si no existe
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())

@app.after_request
def after_request(response):
    if request.path.startswith('/static/'):
        return response
        
    duracion = int((time() - g.inicio) * 1000)  # Duración en milisegundos
    usuario_id = session.get('usuario_id', request.headers.get("X-User-ID", "anonimo"))
    sesion_id = session.get('session_id', request.headers.get("X-Session-ID", str(uuid.uuid4())))
    
    # Recuperar datos adicionales del usuario desde la base de datos
    usuario_data = obtener_datos_usuario(usuario_id) if usuario_id != "anonimo" else {}

    log = {
        "timestamp": datetime.now(),
        "usuario_id": usuario_id,
        "sesion_id": sesion_id,
        "ruta": request.path,
        "metodo": request.method,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        "tiempo_respuesta_ms": duracion,
        "codigo_respuesta": response.status_code,
        "ip_cliente": request.remote_addr,
        "user_agent": request.user_agent.string,
        "usuario_data": usuario_data
    }
    log_queue.put(log)  # Enviar el log a la cola
    return response

def obtener_datos_usuario(usuario_id):
    """
    Función que obtiene datos adicionales de un usuario desde la base de datos.
    """
    try:
        if usuario_id == "anonimo":
            return {}
            
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
        logger.error(f"Error al obtener datos de usuario: {e}")
        return {"error": str(e)}

# --- Endpoint API para consultar datos de logs ---
@app.route("/api/logs", methods=["GET"])
def consultar_logs():
    """
    Endpoint para consultar logs de actividad
    ---
    tags:
      - logs
    parameters:
      - name: usuario_id
        in: query
        type: string
        required: false
        description: ID del usuario
      - name: ruta
        in: query
        type: string
        required: false
        description: Ruta accedida
      - name: desde
        in: query
        type: string
        required: false
        description: Fecha inicio (YYYY-MM-DD)
      - name: hasta
        in: query
        type: string
        required: false
        description: Fecha fin (YYYY-MM-DD)
    responses:
      200:
        description: Logs de actividad
    """
    if 'usuario' not in session or not es_available:
        return jsonify({"error": "No autorizado o Elasticsearch no disponible"}), 403
        
    try:
        # Parámetros de búsqueda
        usuario_id = request.args.get('usuario_id')
        ruta = request.args.get('ruta')
        desde = request.args.get('desde')
        hasta = request.args.get('hasta')
        page = int(request.args.get('page', 1))
        size = int(request.args.get('size', 10))
        
        # Construir query
        query = {"bool": {"must": []}}
        
        if usuario_id:
            query["bool"]["must"].append({"term": {"usuario_id": usuario_id}})
        if ruta:
            query["bool"]["must"].append({"wildcard": {"ruta": f"*{ruta}*"}})
        if desde or hasta:
            range_query = {"range": {"timestamp": {}}}
            if desde:
                range_query["range"]["timestamp"]["gte"] = desde
            if hasta:
                range_query["range"]["timestamp"]["lte"] = hasta
            query["bool"]["must"].append(range_query)
            
        # Si no hay filtros, buscar todo
        if not query["bool"]["must"]:
            query = {"match_all": {}}
            
        # Ejecutar búsqueda
        result = es.search(
            index=INDEX_LOGS,
            body={
                "query": query,
                "sort": [{"timestamp": {"order": "desc"}}],
                "from": (page - 1) * size,
                "size": size
            }
        )
        
        # Procesar resultados
        logs = [hit["_source"] for hit in result["hits"]["hits"]]
        total = result["hits"]["total"]["value"] if "total" in result["hits"] else 0
        
        return jsonify({
            "logs": logs,
            "total": total,
            "page": page,
            "size": size,
            "pages": (total + size - 1) // size
        })
        
    except Exception as e:
        logger.error(f"Error en consulta de logs: {e}")
        return jsonify({"error": str(e)}), 500

# --- Dashboard de estadísticas ---
@app.route("/dashboard/estadisticas")
def dashboard_estadisticas():
    """
    Dashboard con estadísticas de uso
    """
    if 'usuario' not in session:
        return redirect(url_for('login'))
        
    try:
        # Obtener estadísticas usando OLAP en PostgreSQL
        with psycopg2.connect(**db_config) as conn:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                # Total de alumnos por curso (ROLLUP)
                cur.execute("""
                    SELECT c.name as curso, COUNT(ca.alumn_id) as total_alumnos
                    FROM course c
                    LEFT JOIN course_alumn_rel ca ON c.id = ca.course_id
                    GROUP BY ROLLUP(c.name)
                    ORDER BY c.name NULLS LAST
                """)
                alumnos_por_curso = cur.fetchall()
                
                # Promedio de calificaciones por curso y profesor (CUBE)
                cur.execute("""
                    SELECT 
                        COALESCE(c.name, 'TOTAL') as curso,
                        COALESCE(t.name, 'TOTAL') as profesor,
                        ROUND(AVG(ca.calificacion), 2) as promedio_calificacion,
                        COUNT(ca.alumn_id) as total_alumnos
                    FROM course c
                    JOIN teacher t ON c.teacher_id = t.id
                    JOIN course_alumn_rel ca ON c.id = ca.course_id
                    GROUP BY CUBE(c.name, t.name)
                    ORDER BY c.name NULLS LAST, t.name NULLS LAST
                """)
                calificaciones_cube = cur.fetchall()
                
                # Distribución de saldos por rangos
                cur.execute("""
                    SELECT 
                        CASE 
                            WHEN saldo < 0 THEN 'Negativo' 
                            WHEN saldo BETWEEN 0 AND 1000 THEN '0-1000'
                            WHEN saldo BETWEEN 1001 AND 5000 THEN '1001-5000'
                            ELSE 'Más de 5000' 
                        END AS rango_saldo,
                        COUNT(*) as cantidad
                    FROM alumn
                    GROUP BY rango_saldo
                    ORDER BY rango_saldo
                """)
                distribucion_saldos = cur.fetchall()
                
                # Top 5 profesores con más cursos
                cur.execute("""
                    SELECT t.name as profesor, COUNT(c.id) as total_cursos
                    FROM teacher t
                    LEFT JOIN course c ON t.id = c.teacher_id
                    GROUP BY t.name
                    ORDER BY total_cursos DESC
                    LIMIT 5
                """)
                top_profesores = cur.fetchall()
        
        return render_template(
            'dashboard.html',
            alumnos_por_curso=alumnos_por_curso,
            calificaciones_cube=calificaciones_cube,
            distribucion_saldos=distribucion_saldos,
            top_profesores=top_profesores
        )
    except Exception as e:
        logger.error(f"Error en dashboard de estadísticas: {e}")
        return render_template('error.html', error=str(e))

# --- Gráficos estadísticos ---
@app.route('/graficos/alumnos_por_curso')
def grafico_alumnos_por_curso():
    try:
        with psycopg2.connect(**db_config) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT c.name as curso, COUNT(ca.alumn_id) as total_alumnos
                    FROM course c
                    LEFT JOIN course_alumn_rel ca ON c.id = ca.course_id
                    GROUP BY c.name
                    ORDER BY total_alumnos DESC
                    LIMIT 10
                """)
                data = cur.fetchall()
                
                cursos = [row[0] for row in data]
                alumnos = [row[1] for row in data]
                
                plt.figure(figsize=(10, 6))
                plt.bar(cursos, alumnos)
                plt.xlabel('Curso')
                plt.ylabel('Número de Alumnos')
                plt.title('Alumnos por Curso')
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                
                # Convertir gráfico a imagen
                output = io.BytesIO()
                plt.savefig(output, format='png')
                output.seek(0)
                plt.close()
                
                return send_file(output, mimetype='image/png')
    except Exception as e:
        logger.error(f"Error generando gráfico: {e}")
        return "Error generando gráfico", 500

@app.route('/graficos/calificaciones_promedio')
def grafico_calificaciones_promedio():
    try:
        with psycopg2.connect(**db_config) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT c.name as curso, ROUND(AVG(ca.calificacion), 2) as promedio
                    FROM course c
                    JOIN course_alumn_rel ca ON c.id = ca.course_id
                    GROUP BY c.name
                    ORDER BY promedio DESC
                    LIMIT 10
                """)
                data = cur.fetchall()
                
                cursos = [row[0] for row in data]
                promedios = [float(row[1]) for row in data]
                
                plt.figure(figsize=(10, 6))
                plt.bar(cursos, promedios, color='green')
                plt.xlabel('Curso')
                plt.ylabel('Calificación Promedio')
                plt.title('Calificación Promedio por Curso')
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                
                # Convertir gráfico a imagen
                output = io.BytesIO()
                plt.savefig(output, format='png')
                output.seek(0)
                plt.close()
                
                return send_file(output, mimetype='image/png')
    except Exception as e:
        logger.error(f"Error generando gráfico: {e}")
        return "Error generando gráfico", 500

# --- Endpoint para análisis de actividad con Elasticsearch ---
@app.route('/api/analisis/actividad', methods=['GET'])
def analisis_actividad():
    """
    Análisis de actividad de usuarios
    ---
    tags:
      - análisis
    parameters:
      - name: desde
        in: query
        type: string
        required: false
        description: Fecha inicio (YYYY-MM-DD)
      - name: hasta
        in: query
        type: string
        required: false
        description: Fecha fin (YYYY-MM-DD)
    responses:
      200:
        description: Estadísticas de actividad
    """
    if 'usuario' not in session or not es_available:
        return jsonify({"error": "No autorizado o Elasticsearch no disponible"}), 403
        
    try:
        desde = request.args.get('desde', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
        hasta = request.args.get('hasta', datetime.now().strftime('%Y-%m-%d'))
        
        # Análisis por ruta
        result_rutas = es.search(
            index=INDEX_LOGS,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": desde, "lte": hasta}}}
                        ]
                    }
                },
                "aggs": {
                    "rutas": {
                        "terms": {"field": "ruta.keyword", "size": 10},
                        "aggs": {
                            "tiempo_promedio": {"avg": {"field": "tiempo_respuesta_ms"}}
                        }
                    }
                },
                "size": 0
            }
        )
        
        # Análisis por usuario
        result_usuarios = es.search(
            index=INDEX_LOGS,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": desde, "lte": hasta}}},
                            {"bool": {"must_not": [{"term": {"usuario_id": "anonimo"}}]}}
                        ]
                    }
                },
                "aggs": {
                    "usuarios": {
                        "terms": {"field": "usuario_id.keyword", "size": 10},
                        "aggs": {
                            "visitas": {"value_count": {"field": "sesion_id.keyword"}},
                            "rutas_distintas": {"cardinality": {"field": "ruta.keyword"}}
                        }
                    }
                },
                "size": 0
            }
        )
        
        # Análisis por tiempo (histograma)
        result_tiempo = es.search(
            index=INDEX_LOGS,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": desde, "lte": hasta}}}
                        ]
                    }
                },
                "aggs": {
                    "actividad_por_dia": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "day"
                        }
                    }
                },
                "size": 0
            }
        )
        
        return jsonify({
            "rutas_populares": result_rutas["aggregations"]["rutas"]["buckets"],
            "usuarios_activos": result_usuarios["aggregations"]["usuarios"]["buckets"],
            "actividad_por_dia": result_tiempo["aggregations"]["actividad_por_dia"]["buckets"]
        })
        
    except Exception as e:
        logger.error(f"Error en análisis de actividad: {e}")
        return jsonify({"error": str(e)}), 500

# --- SQLite para persistencia local de usuarios ---
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
        """Inicializar la base de datos SQLite"""
        with sqlite3.connect(self.db_name) as db:
            # Tabla de usuarios básica
            db.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                ultimo_acceso TIMESTAMP
            )
            """)
            
            # Tabla para preferencias de usuario
            db.execute("""
            CREATE TABLE IF NOT EXISTS preferencias_usuario (
                usuario_id INTEGER PRIMARY KEY,
                tema TEXT DEFAULT 'claro',
                items_por_pagina INTEGER DEFAULT 30,
                config_json TEXT,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
            )
            """)
            
            # Tabla para datos offline
            db.execute("""
            CREATE TABLE IF NOT EXISTS datos_offline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo TEXT NOT NULL,
                datos_json TEXT NOT NULL,
                sincronizado BOOLEAN DEFAULT 0,
                fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            db.commit()

# --- Servicio de autenticación con SQLite y sesión en Redis ---
class AuthService:
    def __init__(self, db):
        self.db = db

    def register(self, usuario, password):
        """Registro de usuario con validación"""
        if not usuario or not password:
            return {'error': 'Usuario y contraseña son obligatorios'}, 400
            
        if len(password) < 8:
            return {'error': 'La contraseña debe tener al menos 8 caracteres'}, 400
            
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            db = self.db.get_connection()
            db.execute("INSERT INTO usuarios (usuario, password) VALUES (?, ?)", 
                      (usuario, hashed_password))
            db.commit()
            
            # Crear preferencias por defecto
            usuario_id = db.execute("SELECT id FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()['id']
            db.execute("INSERT INTO preferencias_usuario (usuario_id) VALUES (?)", (usuario_id,))
            db.commit()
            
            # Registrar en log
            log = {
                "evento": "registro",
                "usuario": usuario
                
            }
            
            if redis_client:
                redis_client.lpush("logs:registro", json.dumps(log))
                
            return {'message': 'Usuario registrado exitosamente', 'usuario_id': usuario_id}, 201
        except sqlite3.IntegrityError:
            return {'error': 'El usuario ya existe'}, 400
        except Exception as e:
            logger.error(f"Error en registro: {e}")
            return {'error': f'Error en registro: {str(e)}'}, 500

    # (Importaciones al inicio del archivo app.py ya deberían incluir redirect y url_for)
# from flask import redirect, url_for, session, request # Asegúrate que session y request estén disponibles si se usan aquí directamente
# import logging
# logger = logging.getLogger(__name__) # Asumiendo que logger está configurado

# Dentro de la clase AuthService:
    def login(self, usuario, password):
        """Login con gestión de sesión y tracking"""
        logger.info(f"[AuthService.login] Intento de login para usuario: {usuario}")
        try:
            db = self.db.get_connection()
            user = db.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()

            if user and bcrypt.check_password_hash(user['password'], password):
                logger.info(f"[AuthService.login] Contraseña válida para usuario: {usuario}")
                # Actualizar último acceso
                db.execute("UPDATE usuarios SET ultimo_acceso = ? WHERE id = ?",
                           (datetime.now(), user['id']))
                db.commit()

                # Establecer sesión
                session['usuario'] = usuario
                session['usuario_id'] = user['id']
                session.permanent = True # Asegura que la sesión use el lifetime configurado

                logger.info(f"[AuthService.login] Sesión establecida para usuario: {session.get('usuario')}, ID de usuario: {session.get('usuario_id')}")
                logger.debug(f"[AuthService.login] Contenido completo de la sesión: {dict(session)}")

                # Cargar preferencias
                prefs = db.execute("SELECT * FROM preferencias_usuario WHERE usuario_id = ?",
                                   (user['id'],)).fetchone()
                if prefs:
                    session['preferencias'] = dict(prefs)
                    logger.info(f"[AuthService.login] Preferencias cargadas para el usuario: {usuario}")

                # Registrar en log de Redis (si está disponible)
                log_data_redis = {
                    "evento": "login",
                    "usuario": usuario,
                    "usuario_id": user['id'],
                }
                if redis_client:
                    session_data_redis = {
                        "usuario": usuario,
                        "usuario_id": user['id'],
                        "inicio_sesion": datetime.utcnow().isoformat(),
                        "ip": request.remote_addr,
                        "user_agent": request.user_agent.string
                    }
                    redis_key_session_data = f"session_data:{session.get('session_id', 'unknown_session_id')}"
                    redis_client.setex(redis_key_session_data,
                                       app.config['PERMANENT_SESSION_LIFETIME'].total_seconds(),
                                       json.dumps(session_data_redis))
                    logger.info(f"[AuthService.login] Datos de sesión guardados en Redis: {redis_key_session_data}")
                    
                    redis_client.sadd(f"sesiones_activas:{user['id']}", session.get('session_id', 'unknown_session_id'))
                    redis_client.lpush("logs:login", json.dumps(log_data_redis))
                    logger.info(f"[AuthService.login] Evento de login enviado a logs de Redis para usuario: {usuario}")

                logger.info(f"[AuthService.login] Login exitoso. Redirigiendo a 'menu' para usuario: {usuario}")
                return redirect(url_for('menu'))

            else:
                logger.warning(f"[AuthService.login] Credenciales inválidas para usuario: {usuario}")
                # Registrar intento fallido (código de manejo de intentos fallidos y bloqueo ya presente)
                # ... (tu código existente para intentos fallidos) ...
                return {'error': 'Credenciales inválidas'}, 401
        except Exception as e:
            logger.error(f"[AuthService.login] Excepción durante el login para usuario {usuario}: {e}", exc_info=True)
            return {'error': f'Error en login: {str(e)}'}, 500
        
    def logout(self):
        """Cierre de sesión con limpieza de datos"""
        if 'usuario' in session:
            # Registrar en log
            log = {
                "evento": "logout",
                "usuario": session.get('usuario'),
                "usuario_id": session.get('usuario_id'),
                
            }
            
            if redis_client and 'usuario_id' in session and 'session_id' in session:
                # Eliminar datos de sesión
                redis_client.delete(f"session_data:{session['session_id']}")
                # Eliminar de la lista de sesiones activas
                redis_client.srem(f"sesiones_activas:{session['usuario_id']}", session['session_id'])
                redis_client.lpush("logs:logout", json.dumps(log))
        
        # Limpiar sesión
        session.clear()
        return {'message': 'Sesión cerrada'}, 200

    def check_permission(self, required_role=None):
        """Verificar permisos del usuario"""
        if 'usuario' not in session:
            return False
            
        if required_role is None:
            return True
            
        return session.get('rol') == required_role

database = Database()
auth_service = AuthService(database)

@app.teardown_appcontext
def close_connection(exception):
    database.close_connection(exception)

# --- Rutas básicas ---
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
                cur.execute("SELECT id, name, precio, cupo_disponible FROM course limit 1000")
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

config = load_config()



if __name__ == '__main__':
    app.run(debug=True)
import psycopg2

