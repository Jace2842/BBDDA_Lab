from flask import Flask, render_template, request, jsonify
from elasticsearch import Elasticsearch
import logging
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)
es = Elasticsearch("http://localhost:9200")
INDEX = "logs_usuarios"

# Configuración del logger
logger = logging.getLogger("app_logger")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("app.log")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
executor = ThreadPoolExecutor(max_workers=2)

def log_request(data):
    """Registra la solicitud en Elasticsearch de manera asíncrona."""
    try:
        es.index(index="logs", body=data)
    except Exception as e:
        logger.error(f"Error al registrar log en Elasticsearch: {e}")

@app.route('/', methods=['GET', 'POST'])
def index():
    departamento_seleccionado = request.form.get('departamento', 'Ventas')
    query_match = {'query': {'match': {'departamento': departamento_seleccionado}}}
    result = es.search(index='empleados', body=query_match)

    empleados_tabla = [
        {
            'nombre': hit['_source']['nombre'],
            'edad': hit['_source']['edad'],
            'departamento': hit['_source']['departamento']
        }
        for hit in result['hits']['hits']
    ]

    agg_query = {'size': 0, 'aggs': {'por_departamento': {'terms': {'field': 'departamento.keyword'}}}}
    result_agg = es.search(index='empleados', body=agg_query)
    departamentos = [
        {
            'departamento': bucket['key'],
            'cantidad': bucket['doc_count']
        }
        for bucket in result_agg['aggregations']['por_departamento']['buckets']
    ]

    # Registro de log en segundo plano
    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "metodo": request.method,
        "departamento_seleccionado": departamento_seleccionado
    }
    executor.submit(log_request, log_data)
    logger.info(f"Acceso a / con departamento: {departamento_seleccionado}")

    return render_template('index.html', empleados_tabla=empleados_tabla, departamentos=departamentos, departamento_seleccionado=departamento_seleccionado)

@app.route("/api/datos", methods=["GET"])
def consultar_datos():
    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "usuario_id": request.headers.get("X-User-ID", "anonimo"),
        "sesion_id": request.headers.get("X-Session-ID", str(uuid.uuid4())),
        "ruta": request.path,
        "metodo": request.method,
        "parametros": request.args.to_dict() or request.get_json(silent=True),
    }
    executor.submit(log_request, log_data)
    logger.info(f"Acceso a API /api/datos con parámetros: {log_data['parametros']}")
    return jsonify(log_data)

# 1. Obtener todos los logs
def obtener_logs():
    query = {
        "size": 10000,
        "_source": ["timestamp", "funcion", "tiempo_respuesta_ms"],
        "query": {
            "match_all": {}
        }
    }
    res = es.search(index=INDEX, body=query, scroll="2m")
    logs = [hit["_source"] for hit in res["hits"]["hits"]]
    return logs

# 2. Analizar y graficar
def analizar_logs():
    logs = obtener_logs()
    df = pd.DataFrame(logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["fecha"] = df["timestamp"].dt.date

    # Funciones más usadas
    plt.figure()
    top_funcs = df["funcion"].value_counts().head(10)
    top_funcs.plot(kind="barh", title="Funciones más usadas")
    plt.tight_layout()
    img_func_buffer = io.BytesIO()
    plt.savefig(img_func_buffer, format='png')
    img_func_buffer.seek(0)
    img_func_base64 = base64.b64encode(img_func_buffer.getvalue()).decode('utf-8')

    # Tiempo medio por función
    plt.figure()
    tiempos = df.groupby("funcion")["tiempo_respuesta_ms"].mean().sort_values()
    tiempos.plot(kind="bar", title="Tiempo promedio por función (ms)")
    plt.tight_layout()
    img_tiempo_buffer = io.BytesIO()
    plt.savefig(img_tiempo_buffer, format='png')
    img_tiempo_buffer.seek(0)
    img_tiempo_base64 = base64.b64encode(img_tiempo_buffer.getvalue()).decode('utf-8')

    # Tráfico por día
    plt.figure()
    diario = df.groupby("fecha").size()
    diario.plot(title="Número de peticiones por día")
    plt.tight_layout()
    img_diario_buffer = io.BytesIO()
    plt.savefig(img_diario_buffer, format='png')
    img_diario_buffer.seek(0)
    img_diario_base64 = base64.b64encode(img_diario_buffer.getvalue()).decode('utf-8')

    return img_func_base64, img_tiempo_base64, img_diario_base64

@app.route('/analizar_logs', methods=['GET'])
def mostrar_analisis():
    img_func, img_tiempo, img_diario = analizar_logs()
    return render_template('analisis_logs.html', img_func=img_func, img_tiempo=img_tiempo, img_diario=img_diario)

if __name__ == "__main__":
    app.run(debug=True)