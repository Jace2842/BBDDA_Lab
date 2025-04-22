from flask import Flask, request, g,render_template
from time import time
from elasticsearch import Elasticsearch
from datetime import datetime
from threading import Thread
import queue
import uuid
from flask import Flask, request, jsonify, g, render_template, session, redirect, url_for, send_file, make_response,Response
import sqlite3
from flask_bcrypt import Bcrypt
from flasgger import Swagger
import psycopg2
from datetime import datetime

import hashlib
import openpyxl
from io import BytesIO
from flasgger import swag_from
from sqlalchemy import extract, func
import io
import pandas as pd
import pdfkit
import psycopg2
from psycopg2.extras import RealDictCursor







app = Flask(__name__)

es = Elasticsearch("http://localhost:9200")
INDEX_LOGS = "logs_usuarios"
log_queue = queue.Queue()

# --- Worker en segundo plano ---
def worker_logs():
    while True:
        log = log_queue.get()
        if log is None:
            break
        try:
            es.index(index=INDEX_LOGS, body=log)
        except Exception as e:
            print(f"Error al guardar log: {e}")
        log_queue.task_done()

thread = Thread(target=worker_logs, daemon=True)
thread.start()

# --- Middleware Flask ---
@app.before_request
def before_request():
    g.inicio = time()

@app.after_request
def after_request(response):
    duracion = int((time() - g.inicio) * 1000)
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        "tiempo_respuesta_ms": duracion
    }
    log_queue.put(log)
    return response

# --- Endpoint de ejemplo ---




@app.route('/', methods=['GET', 'POST'])
def index():
    departamento_seleccionado = request.form.get('departamento', 'Ventas') # Valor predeterminado: Ventas

    query_match = {'query': {'match': {'departamento': departamento_seleccionado}}}
    result = es.search(index='empleados', body=query_match)

    # Extraer y formatear los resultados
    empleados_tabla = []
    for hit in result['hits']['hits']:
        empleados_tabla.append({
            'nombre': hit['_source']['nombre'],
            'edad': hit['_source']['edad'],
            'departamento': hit['_source']['departamento']
        })

    agg_query = {'size': 0, 'aggs': {'por_departamento': {'terms': {'field': 'departamento.keyword'}}}}
    result_agg = es.search(index='empleados', body=agg_query)

    # Extraer y formatear los resultados de la agregación
    departamentos = []
    for bucket in result_agg['aggregations']['por_departamento']['buckets']:
        departamentos.append({
            'departamento': bucket['key'],
            'cantidad': bucket['doc_count']
        })
    print
    return render_template('index.html', empleados_tabla=empleados_tabla, departamentos=departamentos, departamento_seleccionado=departamento_seleccionado)


@app.route("/api/datos", methods=["GET"])
def consultar_datos():
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "funcion": request.endpoint,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
        
    }
if __name__ == "__main__":
    app.run(debug=True)
